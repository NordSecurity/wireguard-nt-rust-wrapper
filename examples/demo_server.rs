use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use ipnet::Ipv4Net;
use log::*;

fn main() {
    env_logger::init();

    let private = boringtun::crypto::x25519::X25519SecretKey::new();
    let public = private.public_key();

    let (demo_pub, internal_ip, endpoint) =
        get_demo_server_config(public.as_bytes()).expect("Failed to get demo server credentials");
    //Must be run as Administrator because we create network adapters
    //Load the wireguard dll file so that we can call the underlying C functions
    //Unsafe because we are loading an arbitrary dll file
    let wireguard =
        unsafe { wireguard_nt::load_from_path("examples/wireguard_nt/bin/amd64/wireguard.dll") }
            .expect("Failed to load wireguard dll");
    //Try to open an adapter from the given pool with the name "Demo"
    let adapter = match wireguard_nt::Adapter::open(&wireguard, "WireGuard", "Demo") {
        Ok(a) => a,
        Err(_) =>
        //If loading failed (most likely it didn't exist), create a new one
        {
            wireguard_nt::Adapter::create(&wireguard, "WireGuard", "Demo", None)
                .expect("Failed to create wireguard adapter!")
                .adapter
        }
    };
    let mut interface_private = [0; 32];
    let mut peer_pub = [0; 32];

    interface_private.copy_from_slice(private.as_bytes());
    peer_pub.copy_from_slice(demo_pub.as_slice());

    let interface = wireguard_nt::SetInterface {
        listen_port: None,
        public_key: None,
        private_key: Some(interface_private),
        peers: vec![wireguard_nt::SetPeer {
            public_key: Some(peer_pub),
            preshared_key: None,
            keep_alive: Some(21),
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            endpoint,
        }],
    };
    assert!(adapter.set_logging(wireguard_nt::AdapterLoggingLevel::OnWithPrefix));

    match adapter.set_default_route(Ipv4Net::new(internal_ip, 24).unwrap()) {
        Ok(()) => {}
        Err(err) => panic!("Failed to set default route: {}", err),
    }
    assert!(adapter.set_config(interface));
    assert!(adapter.up());

    std::thread::sleep(std::time::Duration::from_secs(30));

    //Delete the adapter when finished.
    adapter.delete().unwrap();
}

/// Gets info from the demo server that can be used to connect.
/// pub_key is a 32 byte public key that corresponds to the private key that the caller has
fn get_demo_server_config(pub_key: &[u8]) -> Result<(Vec<u8>, Ipv4Addr, SocketAddr), String> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    let addrs: Vec<SocketAddr> = "demo.wireguard.com:42912"
        .to_socket_addrs()
        .unwrap()
        .collect();

    let mut s: TcpStream = TcpStream::connect_timeout(
        addrs.get(0).expect("Failed to resolve demo server DNS"),
        Duration::from_secs(5),
    )
    .expect("Failed to open connection to demo server");

    let mut encoded = base64::encode(pub_key);
    encoded.push('\n');
    s.write(encoded.as_bytes())
        .expect("Failed to write public key to server");

    let mut bytes = [0u8; 512];
    let len = s.read(&mut bytes).expect("Failed to read from demo server");
    let reply = &std::str::from_utf8(&bytes).unwrap()[..len].trim();
    info!("Demo server gave: {}", reply);

    if !reply.starts_with("OK") {
        return Err(format!("Demo Server returned error {}", reply));
    }
    let parts: Vec<&str> = reply.split(':').collect();
    if parts.len() != 4 {
        return Err(format!(
            "Demo Server returned wrong number of parts. Expected 4 got: {:?}",
            parts
        ));
    }
    let peer_pub = base64::decode(parts[1])
        .map_err(|e| format!("Demo server gave invalid public key: {}", e))?;

    let endpoint_port: u16 = parts[2]
        .parse()
        .map_err(|e| format!("Demo server gave invalid port number: {}", e))?;

    let internal_ip = parts[3]; 
    let internal_ip: Ipv4Addr = internal_ip.parse().unwrap();

    Ok((
        peer_pub,
        internal_ip,
        SocketAddr::new(addrs[0].ip(), endpoint_port),
    ))
}