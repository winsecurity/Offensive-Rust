use std::{
    io::{Read, Write},
    net::*, sync::mpsc::{self, Receiver}, time::Duration, collections::HashMap,
};

use std::thread;
use std::thread::*;
use std::time;
use bus::{ BusReader};
use bus::Bus;
use async_channel;

fn handleclient(mut clientsocketconnection: &mut TcpStream) {
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



fn handleclient2(mut clientsocketconnection:  TcpStream,
    r3:spmc::Receiver<String>) {
    // after client got connected, we can send banner
    // or receive the message from clientside
    // let's receive the message from clientside
    //let mut buffer: Vec<u8> = vec![0; 1024];
    //clientsocketconnection.read(&mut buffer);
    //println!("received from client: {}", String::from_utf8_lossy(&buffer));

    'serverloop: loop {
       
        let mut userinput = r3.recv().unwrap();
        
       /*'innerloop: loop{
            let res = r3.try_recv();
            if res.is_err(){

            }
            else{
                userinput = res.ok().unwrap();
                break;
            }
       }*/
       
        //println!("the userinput inside handle client: {}",userinput);
        
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
        //std::thread::sleep(Duration::from_millis(10));
        println!("received msg: {}", String::from_utf8_lossy(&buffer));
    }

    // shutting down the client connection
    clientsocketconnection.shutdown(Shutdown::Both);
}



fn sendcommand(mut clientsocketconnection: &mut  TcpStream,
    r3:String) {
    // after client got connected, we can send banner
    // or receive the message from clientside
    // let's receive the message from clientside
    //let mut buffer: Vec<u8> = vec![0; 1024];
    //clientsocketconnection.read(&mut buffer);
    //println!("received from client: {}", String::from_utf8_lossy(&buffer));

    
       
        let mut userinput = r3;
        
       /*'innerloop: loop{
            let res = r3.try_recv();
            if res.is_err(){

            }
            else{
                userinput = res.ok().unwrap();
                break;
            }
       }*/
       
        //println!("the userinput inside handle client: {}",userinput);
        
        if userinput.trim_end_matches("\r\n") == "quit" {
            clientsocketconnection.write_all(
                &mut userinput
                    .trim_end_matches("\r\n")
                    .bytes()
                    .collect::<Vec<u8>>(),
            );
            clientsocketconnection.shutdown(Shutdown::Both);
            //println!("received msg: {}",String::from_utf8_lossy(&buffer));
            
        }

        let mut buffer: Vec<u8> = userinput.trim_end_matches("\r\n").bytes().collect();
        // sending to client
        clientsocketconnection.write_all(&mut buffer);

        let mut buffer: Vec<u8> = vec![0; 4096];
        clientsocketconnection.read(&mut buffer);
        //std::thread::sleep(Duration::from_millis(10));
        println!("received msg: {}", String::from_utf8_lossy(&buffer));
    

    // shutting down the client connection
   // clientsocketconnection.shutdown(Shutdown::Both);
}





use spmc;
use std::collections;

fn main() {
   
    let (mut transmitter, receiver) = spmc::channel::<String>();
    

    let (logger,rx) = mpsc::channel::<TcpStream>();
    let mut connections:Vec<TcpStream> = Vec::new();
    

    thread::spawn(move||{
        loop{
            // connections contains all client sockets
            let res1 = rx.try_recv();
            if res1.is_ok(){
                connections.push(res1.ok().unwrap());
            }

            let res2 = receiver.try_recv();
            if res2.is_ok(){
                let cmd = res2.ok().unwrap();
                for i in 0..connections.len(){
                    sendcommand(&mut connections[i],
                        cmd.clone());
                }
            }
            
            //println!("{:?}",connections);

            


        }
    });



    // THREAD2
    let serversockethandlethread = thread::spawn(move ||{

        let ipaddr = Ipv4Addr::new(127, 0, 0, 1);
        let socketaddress = SocketAddrV4::new(ipaddr, 1234);
        let listener = TcpListener::bind(socketaddress).unwrap();
        //listener.set_nonblocking(true).expect("setting listener to nonblocking failed");
        
       let mut uinput = String::new();
       //let r2 = receiver.clone();

       let logger2 = logger.clone();
        

       // THREAD3
        let connhandle = thread::spawn( move||{

            
            //let r3 = r2.clone();
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
    
                logger2.send(clientsocketconnection);



                
                /*let r4 = r3.clone();
            
              
               
                
               let clienthandle = thread::spawn(move ||{

                    handleclient2(clientsocketconnection,r4.clone());
            });*/
                
            }
            

        }); 
        
        /*loop{
             uinput= receiver.recv().unwrap();
            print!("received from user: {}",uinput);
            //transmitter.send(uinput).unwrap();
            
         }*/

    });
    
    // infinitely asking userinput
   
    loop{
        
        println!("Enter command: ");
        //std::io::stdout().flush().unwrap();
        let mut uinput = String::new();
        std::io::stdin().read_line(&mut uinput).unwrap();

        // sends the userinput to the serversocket main thread
        transmitter.send(uinput.clone());
       ;

        // delay to print the output from the thread2.
        //std::thread::sleep(Duration::from_millis(1));
    }
    





    /*let (clientsocketstream, clientaddress ) = listener.accept().unwrap();

        println!("Incoming client connected: {}:{}",clientaddress.ip(),clientaddress.port());

        clientsocketstream.shutdown(Shutdown::Both);
    */
}
