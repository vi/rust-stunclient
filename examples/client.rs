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

    let u = std::net::UdpSocket::bind("0.0.0.0:0".parse::<std::net::SocketAddrV4>().unwrap()).unwrap();

    match sc.query_external_address(&u) {
        Ok(x) => println!("{}", x),
        Err(e) => {
            eprintln!("{}", e);
            return Err(());
        }
    }
    Ok(())
}
