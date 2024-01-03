use std::{
    io::{Read, Write},
    net::*,
};

fn handleclient(mut clientsocketconnection: TcpStream) {
    // after client got connected, we can send banner
    // or receive the message from clientside
    // let's receive the message from clientside
    let mut buffer: Vec<u8> = vec![0; 1024];
    clientsocketconnection.read(&mut buffer);
    println!("received from client: {}", String::from_utf8_lossy(&buffer));

    'serverloop: loop {
        let mut userinput = String::new();
        std::io::stdin().read_line(&mut userinput).unwrap();

        if userinput.trim_end_matches("\r\n") == "quit" {
            clientsocketconnection.write_all(
                &mut userinput
                    .trim_end_matches("\r\n")
                    .bytes()
                    .collect::<Vec<u8>>(),
            );
            //println!("received msg: {}",String::from_utf8_lossy(&buffer));
            break 'serverloop;
        }

        let mut buffer: Vec<u8> = userinput.trim_end_matches("\r\n").bytes().collect();
        // sending to client
        clientsocketconnection.write_all(&mut buffer);

        let mut buffer: Vec<u8> = vec![0; 4096];
        clientsocketconnection.read(&mut buffer);

        println!("received msg: {}", String::from_utf8_lossy(&buffer));
    }

    // shutting down the client connection
    clientsocketconnection.shutdown(Shutdown::Both);
}

fn main() {
    let ipaddr = Ipv4Addr::new(127, 0, 0, 1);

    let socketaddress = SocketAddrV4::new(ipaddr, 1234);

    let listener = TcpListener::bind(socketaddress).unwrap();

    // incoming() will do infinite loop on accept() and
    // throws us the tcpstream object of incoming client connection
    for clientconnection in listener.incoming() {
        let mut clientsocketconnection = match clientconnection {
            Ok(s) => s,
            Err(e) => {
                println!("{}", e);
                continue;
            }
        };

        println!(
            "[+] Client connected: [{}:{}]",
            clientsocketconnection.peer_addr().unwrap().ip(),
            clientsocketconnection.peer_addr().unwrap().port()
        );

        handleclient(clientsocketconnection);
    }

    /*let (clientsocketstream, clientaddress ) = listener.accept().unwrap();

        println!("Incoming client connected: {}:{}",clientaddress.ip(),clientaddress.port());

        clientsocketstream.shutdown(Shutdown::Both);
    */
}
