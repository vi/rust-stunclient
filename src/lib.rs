//! Simple UDP-only STUN client for resolving external IP address:port behind NAT.
#![deny(missing_docs)]

use stun_codec::{MessageDecoder, MessageEncoder};

use bytecodec::{DecodeExt, EncodeExt};
use std::fmt;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;
use stun_codec::rfc5389::attributes::{
    // XorMappedAddress2,
    MappedAddress,
    Software,
    XorMappedAddress,
};
use stun_codec::rfc5389::{methods::BINDING, Attribute};
use stun_codec::{Message, MessageClass, TransactionId};

/// The error type for any [`StunClient`] operations
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Could not encode or decode message
    Bytecodec(bytecodec::Error),
    /// Broken STUN message
    Stun(stun_codec::BrokenMessage),
    /// No XorMappedAddress or MappedAddress in STUN reply
    NoAddress(()),
    /// UDP socket error
    Socket(std::io::Error),
    /// Time out while reading socket
    Timeout(()),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Bytecodec(_) => "Could not encode or decode message",
            Error::Stun(_) => "Broken STUN message",
            Error::NoAddress(_) => "No XorMappedAddress or MappedAddress in STUN reply",
            Error::Socket(_) => "UDP socket error",
            Error::Timeout(_) => "Time out while reading socket",
        })
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Stun(_) | Error::NoAddress(_) | Error::Timeout(_) => None,
            Error::Bytecodec(err) => Some(err),
            Error::Socket(err) => Some(err),
        }
    }
}

/// Options for querying STUN server
pub struct StunClient {
    /// "End-to-end" timeout for the operation.
    pub timeout: Duration,
    /// How often to repeat STUN binding requests
    pub retry_interval: Duration,
    /// Address of the STUN server
    pub stun_server: SocketAddr,
    /// `SOFTWARE` attribute value in binding request
    pub software: Option<&'static str>,
}

impl StunClient {
    /// A constructor with default parameters
    pub fn new(stun_server: SocketAddr) -> Self {
        StunClient {
            timeout: Duration::from_secs(10),
            retry_interval: Duration::from_secs(1),
            stun_server,
            software: Some("SimpleRustStunClient"),
        }
    }

    /// Use hard coded STUN server `stun.l.google.com:19302`.
    ///
    /// Not for production use, for tests, prototypes and demos.
    /// May block the thread.
    /// May panic in case of address resolution problems.
    pub fn with_google_stun_server() -> Self {
        use std::net::ToSocketAddrs;
        let stun_server = "stun.l.google.com:19302"
            .to_socket_addrs()
            .unwrap()
            .filter(|x| x.is_ipv4())
            .next()
            .unwrap();
        StunClient::new(stun_server)
    }

    /// Set `timeout` field, builder pattern.
    pub fn set_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.timeout = timeout;
        self
    }

    /// Set `retry_interval` field, builder pattern.
    pub fn set_retry_interval(&mut self, retry_interval: Duration) -> &mut Self {
        self.retry_interval = retry_interval;
        self
    }

    /// Set `software` field, builder pattern.
    pub fn set_software(&mut self, software: Option<&'static str>) -> &mut Self {
        self.software = software;
        self
    }
}

impl StunClient {
    fn get_binding_request(&self) -> Result<Vec<u8>, Error> {
        use rand::Rng;
        let random_bytes = rand::thread_rng().gen::<[u8; 12]>();

        let mut message: Message<Attribute> = Message::new(
            MessageClass::Request,
            BINDING,
            TransactionId::new(random_bytes),
        );

        if let Some(s) = self.software {
            message.add_attribute(Attribute::Software(
                Software::new(s.to_owned()).map_err(Error::Bytecodec)?,
            ));
        }

        // Encodes the message
        let mut encoder = MessageEncoder::new();
        let bytes = encoder
            .encode_into_bytes(message.clone())
            .map_err(Error::Bytecodec)?;
        Ok(bytes)
    }

    fn decode_address(buf: &[u8]) -> Result<SocketAddr, Error> {
        let mut decoder = MessageDecoder::<Attribute>::new();
        let decoded = decoder
            .decode_from_bytes(buf)
            .map_err(Error::Bytecodec)?
            .map_err(Error::Stun)?;

        //eprintln!("Decoded message: {:?}", decoded);

        let external_addr1 = decoded
            .get_attribute::<XorMappedAddress>()
            .map(|x| x.address());
        //let external_addr2 = decoded.get_attribute::<XorMappedAddress2>().map(|x|x.address());
        let external_addr3 = decoded
            .get_attribute::<MappedAddress>()
            .map(|x| x.address());
        let external_addr = external_addr1
            // .or(external_addr2)
            .or(external_addr3);
        let external_addr = external_addr.ok_or_else(|| Error::NoAddress(()))?;

        Ok(external_addr)
    }

    /// Get external (server-reflexive transport address) IP address and port of specified UDP socket
    pub fn query_external_address(&self, udp: &UdpSocket) -> Result<SocketAddr, Error> {
        let stun_server = self.stun_server;

        let bytes = self.get_binding_request()?;

        udp.send_to(&bytes[..], stun_server)
            .map_err(Error::Socket)?;

        let mut buf = [0; 256];

        let old_read_timeout = udp.read_timeout().map_err(|_| Error::Timeout(()))?;
        let mut previous_timeout = None;

        use std::time::Instant;

        let deadline = Instant::now() + self.timeout;
        loop {
            let now = Instant::now();
            if now >= deadline {
                udp.set_read_timeout(old_read_timeout)
                    .map_err(Error::Socket)?;
                return Err(Error::Timeout(()));
            }
            let mt = self.retry_interval.min(deadline - now);
            if Some(mt) != previous_timeout {
                previous_timeout = Some(mt);
                udp.set_read_timeout(previous_timeout)
                    .map_err(Error::Socket)?;
            }

            let (len, addr) = match udp.recv_from(&mut buf[..]) {
                Ok(x) => x,
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    udp.send_to(&bytes[..], stun_server)
                        .map_err(Error::Socket)?;
                    continue;
                }
                Err(e) => return Err(Error::Socket(e)),
            };
            let buf = &buf[0..len];

            //eprintln!("Received reply from {:?}", addr);

            if addr != stun_server {
                continue;
            }

            let external_addr = StunClient::decode_address(buf)?;

            udp.set_read_timeout(old_read_timeout)
                .map_err(Error::Socket)?;
            return Ok(external_addr);
        }
    }

    #[cfg(feature = "async")]
    async fn query_external_address_async_impl(
        &self,
        udp: &tokio::net::UdpSocket,
    ) -> Result<SocketAddr, Error> {
        let mut interval = tokio::time::interval(self.retry_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let rq = self.get_binding_request()?;
        let mut buf = [0u8; 256];

        loop {
            tokio::select! {
                biased; // to make impl simpler
                _t = interval.tick() => {
                    udp.send_to(&rq[..], &self.stun_server).await.map_err(Error::Socket)?;
                }
                c = udp.recv_from(&mut buf[..]) => {
                    let (len, from) = c.map_err(Error::Socket)?;
                    if from != self.stun_server {
                        continue;
                    }
                    let buf = &buf[0..len];
                    let external_addr = StunClient::decode_address(buf)?;
                    return Ok(external_addr);
                }
            }
        }
    }

    /// async version of `query_external_address`.
    ///
    /// Requires `async` crate feature to be enabled (it is by default)
    #[cfg(feature = "async")]
    pub async fn query_external_address_async(
        &self,
        udp: &tokio::net::UdpSocket,
    ) -> Result<SocketAddr, Error> {
        let timeout = self.timeout;
        let ret = tokio::time::timeout(timeout, self.query_external_address_async_impl(udp)).await;
        match ret {
            Ok(Ok(x)) => Ok(x),
            Ok(Err(e)) => Err(e),
            Err(_elapsed) => Err(Error::Timeout(()))?,
        }
    }
}

/// Super-simple function with everything hard coded:
/// just return `UdpSocket` and its external address in one step
/// May block, may panic, uses public Google STUN server.
pub fn just_give_me_the_udp_socket_and_its_external_address() -> (UdpSocket, SocketAddr) {
    let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let udp = UdpSocket::bind(local_addr).unwrap();

    let c = StunClient::with_google_stun_server();

    let addr = c.query_external_address(&udp).unwrap();
    (udp, addr)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let (_udp, myip) = super::just_give_me_the_udp_socket_and_its_external_address();
        println!("{:?}", myip);
    }

    #[cfg(feature = "async")]
    #[tokio::test(flavor = "current_thread")]
    async fn it_works_async() {
        use std::net::SocketAddr;
        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let udp = tokio::net::UdpSocket::bind(&local_addr).await.unwrap();

        let s = super::StunClient::with_google_stun_server();
        let f = s.query_external_address_async(&udp);
        let q = f.await;
        assert!(q.is_ok());
        println!("{}", q.unwrap())
    }
}
