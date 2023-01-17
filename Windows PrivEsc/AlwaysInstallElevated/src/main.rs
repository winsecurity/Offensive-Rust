
use registry::*;

fn main() {

    println!("[+] Checking AlwaysInstallElevated in Registry");

{
    let regpath = r#"SOFTWARE\Policies\Microsoft\Windows\Installer"#;

    let res = Hive::LocalMachine.open(regpath, Security::Read);

    let regkey = match res{
        Ok(regkey) => regkey,
        Err(e) => { println!("LocalMachine -> {}",e); std::process::exit(0);}
    };

    let v = regkey.value("AlwaysInstallElevated");

    match v{
        Ok(data1) => println!("LocalMachine -> AlwaysInstallElevated -> {}",data1),
        Err(e) =>  { println!("{}",e)}
    };

}








{
    let regpath = r#"SOFTWARE\Policies\Microsoft\Windows\Installer"#;

    let res = Hive::CurrentUser.open(regpath, Security::Read);

    let regkey = match res{
        Ok(regkey) => regkey,
        Err(e) => { println!("CurrentUser ->{}",e); std::process::exit(0);}
    };

    let v = regkey.value("AlwaysInstallElevated");

    match v{
        Ok(data1) => println!("CurrentUser -> AlwaysInstallElevated -> {}",data1),
        Err(e) =>  { println!("{}",e)}
    };

}


    /*for i in regkey.values(){
        println!("{:x?} -> {:x?}",
        i.as_ref().unwrap().name().to_string(),
        i.as_ref().unwrap().data().to_string());
    }*/


}
