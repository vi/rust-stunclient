//! Simple UDP-only STUN client for resolving external IP address:port behind NAT.
//! 
//! Currently it supports no async, no retries, no timeouts, no additional options
//! 
//! Open Github issue/pull request if you such features.

#![deny(missing_docs)]

extern crate bytecodec;
extern crate stun_codec;
extern crate rand;

use stun_codec::{MessageDecoder, MessageEncoder};

use bytecodec::{DecodeExt, EncodeExt};
use std::net::{SocketAddr, UdpSocket};
use stun_codec::rfc5389::attributes::{Software, XorMappedAddress, XorMappedAddress2, MappedAddress};
use stun_codec::rfc5389::{methods::BINDING, Attribute};
use stun_codec::{Message, MessageClass, TransactionId};

/// Get external (server-reflexive transport address) IP address and port of this UDP socket
/// by sending one UDP packet to specified STUN server and waiting for one reply without any timeout
pub fn get_external_ip_of_this_socket(
    udp: &UdpSocket,
    stun_server: SocketAddr,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {


    use rand::Rng;
    let random_bytes = rand::thread_rng().gen::<[u8; 12]>();

    let mut message = Message::new(MessageClass::Request, BINDING, TransactionId::new(random_bytes));
    message.add_attribute(Attribute::Software(Software::new(
        "SimpleRustStunClient".to_owned(),
    )?));

    // Encodes the message
    let mut encoder = MessageEncoder::new();
    let bytes = encoder.encode_into_bytes(message.clone())?;

    udp.send_to(&bytes[..], stun_server)?;

    let mut buf = [0; 256];

    loop {
        let (len, addr) = udp.recv_from(&mut buf[..])?;
        let buf = &buf[0..len];

        //eprintln!("Received reply from {:?}", addr);

        if addr != stun_server {
            continue;
        }

        let mut decoder = MessageDecoder::<Attribute>::new();
        let decoded = decoder
            .decode_from_bytes(buf)?
            .map_err(|_| format!("Broken STUN reply"))?;

        //eprintln!("Decoded message: {:?}", decoded);

        let external_addr1 = decoded.get_attribute::<XorMappedAddress>().map(|x|x.address());
        let external_addr2 = decoded.get_attribute::<XorMappedAddress2>().map(|x|x.address());
        let external_addr3 = decoded.get_attribute::<MappedAddress>().map(|x|x.address());
        let external_addr = external_addr1.or(external_addr2).or(external_addr3);
        let external_addr = external_addr.ok_or_else(||format!("No XorMappedAddress or MappedAddress in STUN reply"))?;

        return Ok(external_addr)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
    #[test]
    fn it_works() {
        let local_addr : SocketAddr = "0.0.0.0:0".parse().unwrap();
        let udp = UdpSocket::bind(local_addr).unwrap();
        let stun_server = "stun.l.google.com:19302".to_socket_addrs().unwrap().filter(|x|x.is_ipv4()).next().unwrap();
        let myip = super::get_external_ip_of_this_socket(&udp, stun_server);
        println!("{:?}", myip);
        assert!(myip.is_ok());
    }
}
