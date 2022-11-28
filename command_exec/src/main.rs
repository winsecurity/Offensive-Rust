
use std::env;
use std::process::Command;

fn executecmd(cmd:&str) -> String{
    let temp = "/c ".to_owned();
    let fullcmd = temp + cmd;

    let  cmds = fullcmd.split(" ").collect::<Vec<&str>>();
    //println!("{:#?}",cmds);

    let res =Command::new("cmd.exe").args(&cmds)
            .output().expect("string expected");
    let stdout =String::from_utf8_lossy(res.stdout.as_slice());
    let stderr =String::from_utf8_lossy(res.stderr.as_slice());

    if stdout.len()>0{
        return stdout.to_string();
    }
    else{
        return stderr.to_string();
    }

    
}


fn main() {
    
    let args: Vec<String> = env::args().collect();
    if args.len() == 2{
        let result = executecmd(&args[1]);
        println!("{}",result);
    }
    else{
        println!("[+] Usage {} command",args[0]);
    }
    

}
