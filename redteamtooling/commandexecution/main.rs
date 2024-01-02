
use std::process::Command;

fn main() {
    
    let mut arguments = std::env::args().collect::<Vec<String>>();
    arguments.remove(0);
    arguments.insert(0, "/c".to_string());


    let cmd = Command::new("cmd")
        .args(arguments).output().expect("failed to execute");
    
    if cmd.stdout.len()>0{
        println!("{}",String::from_utf8_lossy( &cmd.stdout));
    }
    else if cmd.stderr.len()>0{
        println!("{}",String::from_utf8_lossy( &cmd.stderr));
    }
    else{
        
    }


}
