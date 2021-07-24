Simple UDP-only STUN client for resolving external IP address:port behind NAT.

Supports both sync and async.

Example (sync):

```rust
use std::net::UdpSocket;
use stunclient::StunClient;
use std::net::{SocketAddr,ToSocketAddrs};
let local_addr : SocketAddr = "0.0.0.0:0".parse().unwrap();
let stun_addr = "stun.l.google.com:19302".to_socket_addrs().unwrap().filter(|x|x.is_ipv4()).next().unwrap();
let udp = UdpSocket::bind(local_addr).unwrap();

let c = StunClient::new(stun_addr);

let my_external_addr = c.query_external_address(&udp).unwrap();
```

Example (async):

```rust
use stunclient::StunClient;
use std::net::{SocketAddr,ToSocketAddrs};

let local_addr : SocketAddr = "0.0.0.0:0".parse().unwrap();
let stun_addr = "stun.l.google.com:19302".to_socket_addrs().unwrap().filter(|x|x.is_ipv4()).next().unwrap();
let udp = tokio::net::udp::UdpSocket::bind(&local_addr).unwrap();

let c = StunClient::new(stun_addr);
let f = c.query_external_address_async(&udp);
let my_external_addr = f.await.unwrap();
```

Old version (0.1) of stunclient is almost the same, but is for Tokio `0.1`.
