#![allow(unused)]

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::*,
};

fn main() {

    // ip and port to listen on
    let ipaddress = "127.0.0.1";
    let port = 6969;

    // parsing ip address into ipv4addr
    let ip = match ipaddress.parse::<Ipv4Addr>() {
        Ok(ip) => ip,
        Err(e) => panic!("{}", e),
    };

    // creating a socket address structure
    let bindaddress = SocketAddrV4::new(ip, port);

    // binding to the ip and port we specified
    let tcplistener = match TcpListener::bind(bindaddress) {
        Ok(l) => l,
        Err(e) => panic!("{}", e),
    };

    println!(
        "the address we are listening on: {:?}",
        tcplistener.local_addr().unwrap()
    );

    // accepting the incoming connections
    let (mut clientstream, clientaddress) = match tcplistener.accept() {
        Ok(a) => {
            println!("[+] A client connected: {:?}", a.1);
            a
        }
        Err(e) => panic!("{}", e),
    };

    // printing the local and peer connections
    println!(
        "local address of client: {:?}",
        clientstream.local_addr().expect("socket addr expected")
    );
    println!(
        "peer address of client: {:?}",
        clientstream.peer_addr().unwrap()
    );

    // creating a bufferreader to read from socket tcpstream
    let mut clientreader = BufReader::new(&clientstream);
    let mut buf: Vec<u8> = vec![0; 1024];
    let bytesread = clientreader
        .read_until(b'\0', &mut buf)
        .expect("read failed from the client");

    println!(
        "received from {:?}: {}",
        clientstream.peer_addr(),
        String::from_utf8_lossy(&buf)
    );


    print!("Enter cmd to send to {:?}>", clientaddress);
    let mut payload = String::new();
    std::io::stdin()
        .read_line(&mut payload)
            .expect("expected string input");
    //payload.trim_end_matches('\n');
    payload.push('\0');
    clientstream.write(&payload.as_bytes());

    println!("you sent: {}",payload);


    

    loop{
        //if payload.trim_end_matches('\0').trim()=="quit"{
        //    break;
       // }
        let mut clientreader = BufReader::new(&clientstream);
        let mut buf: Vec<u8> = Vec::new();
        let bytesread = clientreader
            .read_until(b'\0', &mut buf)
            .expect("read failed from the client");

        let output = String::from_utf8_lossy(&buf);
        println!(
                "received from {:?}: \"{}\"",
                clientstream.peer_addr().unwrap(),
                output.trim_end_matches('\0').trim()
            );


        if output.trim_end_matches('\0').trim()=="quitting"{
                    break;
                } 


          //  println!("payload trim end matches\0 : {}",payload.trim_end_matches('\0').trim());
        println!("{:?}>", clientaddress);
        let mut payload = String::new();
        std::io::stdin()
            .read_line(&mut payload)
                .expect("expected string input");
        payload.push('\0');
        clientstream.write(&payload.as_bytes());
        

        //println!("you sent: {}",payload);

    }


    clientstream.shutdown(Shutdown::Both);
}


/*

    if bytesread > 0 {
        loop {
            println!("Enter something to send to {:?}", clientaddress);
            let mut payload = String::new();
            std::io::stdin()
                .read_line(&mut payload)
                .expect("expected string input");
            payload.push('\0');
            clientstream.write(&payload.as_bytes());

            let mut buffer:Vec<u8> = Vec::new();
            clientreader.read_until(b'\0', &mut buffer).expect(" ");
            let output = String::from_utf8_lossy(&buffer);

            if payload.trim_end_matches('\0') == "quit" {
                break;
            }
        }
    } */