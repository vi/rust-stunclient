use stunclient::StunClient;

fn main() -> Result<(), ()> {
    let args : Vec<_> = std::env::args().collect();
    if args.len() > 2 || args.get(1).map(|x|&x[..]) == Some("--help") {
        eprintln!("Usage: client [stun_server_socket_address]");
        return Err(());
    }
    let sc = if let Some(x) = args.get(1) {
        if let Ok(xx) = x.parse() {
            StunClient::new(xx)
        } else {
            eprintln!("Failed to parse socket address");
            return Err(());
        }
    } else {
        StunClient::with_google_stun_server()
    };

    let mut t = tokio::runtime::current_thread::Runtime::new().unwrap();
    let u = tokio_udp::UdpSocket::bind(&"0.0.0.0:0".parse::<std::net::SocketAddr>().unwrap()).unwrap();

    let ret = sc.query_external_address_async(u);

    match t.block_on(ret) {
        Ok((_u,x)) => println!("{}", x),
        Err(e) => {
            eprintln!("{}", e);
            return Err(());
        }
    }
    Ok(())
}
