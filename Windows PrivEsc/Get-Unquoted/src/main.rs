use std::collections::HashMap;
use std::fmt::Write;
use std::hash::Hash;
use std::io::Read;

use winapi::shared::minwindef::HINSTANCE;
use winapi::shared::windef::HWND__;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::*;
use winapi::um::memoryapi::*;
use winapi::um::libloaderapi::*;
use winapi::um::winnt::IMAGE_IMPORT_BY_NAME;
use winapi::um::winnt::SERVICE_WIN32;
use winapi::um::winuser::*;
use winapi::um::winuser::MessageBoxA;
use winapi::ctypes::*;
use winapi::um::tlhelp32::*;
use winapi::um::winsvc::*;




fn main() {
    

    unsafe{

  
    let schandle =OpenSCManagerA(
        std::ptr::null(), 
        std::ptr::null() , SC_MANAGER_ENUMERATE_SERVICE);
    
        println!("schandle: {:x?}",schandle);


        let mut bytesneeded = 0;
        let mut numofservices = 0;
        EnumServicesStatusExA(
            schandle, 
            SC_ENUM_PROCESS_INFO, 
            SERVICE_WIN32, 
            SERVICE_STATE_ALL, 
            std::ptr::null_mut(), 
            0, 
            &mut bytesneeded, 
            &mut numofservices, 
            std::ptr::null_mut(), 
            std::ptr::null_mut());


            println!("bytes needed: {}",bytesneeded);
            println!("number of services : {}",numofservices);

       let baseptr = VirtualAlloc(std::ptr::null_mut(), bytesneeded as usize, 0x1000|0x2000, 0x40);

            EnumServicesStatusExA(
            schandle, 
            SC_ENUM_PROCESS_INFO, 
            SERVICE_WIN32, 
            SERVICE_STATE_ALL, 
            baseptr as *mut u8, 
            bytesneeded, 
            &mut bytesneeded, 
            &mut numofservices, 
            std::ptr::null_mut(), 
            std::ptr::null_mut());

            println!("bytes needed: {}",bytesneeded);
            println!("number of services : {}",numofservices);


            //let mut enumservices = std::mem::zeroed::<ENUM_SERVICE_STATUS_PROCESSA>();
            for i in 0..numofservices{

                           
            let mut enumservices = (*((baseptr as isize + (i as isize *std::mem::size_of::<ENUM_SERVICE_STATUS_PROCESSA>() as isize)) as *mut ENUM_SERVICE_STATUS_PROCESSA));

              let dname =  ReadStringFromMemory(GetCurrentProcess(), enumservices.lpDisplayName as *mut c_void);
                let sname =  ReadStringFromMemory(GetCurrentProcess(), enumservices.lpServiceName as *mut c_void);
              //println!(" service display name: {}",dname);
              println!("service name: {}, pid: {}",sname,enumservices.ServiceStatusProcess.dwProcessId);
            
              let servicehandle =  OpenServiceA(schandle, 
                    enumservices.lpServiceName, SERVICE_QUERY_CONFIG);
            
            
                    let mut sbytes = 0;
                    QueryServiceConfigA(
                    servicehandle, 
                    std::ptr::null_mut(), 
                    0, &mut sbytes);

                    let sbase =VirtualAlloc(std::ptr::null_mut(), sbytes as usize, 0x1000|0x2000, 0x40);


                    QueryServiceConfigA(
                        servicehandle, 
                        sbase as *mut QUERY_SERVICE_CONFIGA, 
                        sbytes, &mut sbytes);


                        let sconfig = (*(sbase as *mut QUERY_SERVICE_CONFIGA));

                        let binpath = ReadStringFromMemory(GetCurrentProcess(), sconfig.lpBinaryPathName as *mut c_void);
                        
                        if !binpath.contains("\""){
                        
                        println!("binary path: {}",binpath);
                        }


                        VirtualFree(sbase, 0, 0x8000);
            

            } 
            VirtualFree(baseptr, 0, 0x8000);
            

        /*let mut bytesneeded = 0;

        let res = QueryServiceConfigA(schandle, 
            std::ptr::null_mut(), 
            0, &mut bytesneeded);

            println!("res: {}",res);
            println!("getlasterror: {}",GetLastError());
            println!("bytes needed: {}",bytesneeded );
            */
    
    
    }
}



pub fn FillStructureFromArray<T, U>(base: &mut T, arr: &[U]) -> usize {
    unsafe {
        //println!("{}",std::mem::size_of::<T>());
        //println!("{}",std::mem::size_of_val(arr));
        if std::mem::size_of::<T>() != std::mem::size_of_val(arr) {
            println!("{}", std::mem::size_of::<T>());
            println!("{}", std::mem::size_of_val(arr));
            panic!("sizes are not equal to copy");
        }

        let mut handle = GetCurrentProcess();
        let mut byteswritten = 0;
        let res = WriteProcessMemory(
            handle,
            base as *mut _ as *mut c_void,
            arr as *const _ as *const c_void,
            std::mem::size_of::<T>(),
            &mut byteswritten,
        );

        return byteswritten;
    }
}

pub fn FillStructureFromMemory<T>(
    dest: &mut T,
    src: *const c_void,
    prochandle: *mut c_void,
) -> usize {
    unsafe {
        let bytestoread: usize = std::mem::size_of::<T>();
        //println!("size of structure is {}",bytestoread);
        let mut buffer: Vec<u8> = vec![0; bytestoread];
        let mut byteswritten = 0;

        let res = ReadProcessMemory(
            prochandle,
            src,
            buffer.as_mut_ptr() as *mut c_void,
            bytestoread,
            &mut byteswritten,
        );
        //println!("array being filled: {:x?}",&buffer);
        FillStructureFromArray(dest, &buffer);

        return byteswritten;
    }
}


pub fn ReadStringFromMemory(prochandle: *mut c_void, base: *const c_void) -> String {
    unsafe {
        let mut i: isize = 0;
        let mut s = String::new();
        loop {
            let mut a: [u8; 1] = [0];
            ReadProcessMemory(
                prochandle,
                (base as isize + i) as *const c_void,
                a.as_mut_ptr() as *mut c_void,
                1,
                std::ptr::null_mut(),
            );

            if a[0] == 0 || i == 256 {
                return s;
            }
            s.push(a[0] as char);
            i += 1;
        }
    }
}

