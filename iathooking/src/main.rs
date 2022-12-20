use std::collections::HashMap;
use std::fmt::Write;
use std::io::Read;

use winapi::shared::windef::HWND__;
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::*;
use winapi::um::memoryapi::*;
use winapi::um::libloaderapi::*;
use winapi::um::winnt::IMAGE_IMPORT_BY_NAME;
use winapi::um::winuser::*;
use winapi::um::winuser::MessageBoxA;
use winapi::ctypes::*;
use winapi::um::tlhelp32::*;



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

/*pub fn ReadStringFromMemory(phandle:*mut c_void,baseaddress:*const c_void,) -> String{

    let mut temp:Vec<u8> = vec![0;100];
    let mut bytesread:usize = 0;
    unsafe{
        let mut i = 0;
        loop{
        let res =ReadProcessMemory(phandle,
            (baseaddress as isize+i) as *const c_void, 
        (temp.as_mut_ptr() as usize + i as usize) as *mut c_void,
            1,
            &mut bytesread );
            

            if temp[i as usize]==0{
                //println!("{:x?}",i);
                break;
            }
            i +=1;
    }
    let dllname =String::from_utf8_lossy(&temp);
    dllname.to_string()
    }
}*/



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

            if a[0] == 0 || i == 50 {
                return s;
            }
            s.push(a[0] as char);
            i += 1;
        }
    }
}

pub fn GetStringFromu8Array(arr: &mut [u8]) -> String {
    let mut temp = String::new();

    for i in 0..arr.len() {
        if arr[i] == 0 {
            return temp;
        } else {
            temp.push(arr[i] as u8 as char);
        }
    }

    temp
}

pub fn GetStringFromi8Array(arr: &mut [i8]) -> String {
    let mut temp = String::new();

    for i in 0..arr.len() {
        if arr[i] == 0 {
            return temp;
        } else {
            temp.push(arr[i] as u8 as char);
        }
    }

    temp
}


use winapi::um::errhandlingapi::*;
use std::ffi::{CString};
//use dll_syringe::{Syringe,process::OwnedProcess};


/*pub fn DllInject(prochandle:*mut c_void,dllpath:&str){



    unsafe{

       let targetproc= OwnedProcess::find_first_by_name("sample.exe").unwrap();
     
       let s =Syringe::for_process(targetproc);
        
       let payload= s.inject(dllpath).unwrap();
       /*  println!("dllpath : {}",dllpath);

    let remotebase =VirtualAllocEx(prochandle,
std::ptr::null_mut(),dllpath.len(),
    0x1000,0x40);

        let mut byteswritten = 0;

    WriteProcessMemory(prochandle,
    remotebase, 
    dllpath.as_bytes().as_ptr() as *const c_void, 
    dllpath.len(), &mut byteswritten as *mut _ as *mut usize);

        println!("bytes written: {}",byteswritten);


        let dllhandle =GetModuleHandleA("kernel32.dll\0".as_ptr() as *const i8);

        let funcaddr =GetProcAddress(dllhandle, "LoadLibraryA\0".as_ptr() as *const i8);

        CreateRemoteThread(prochandle, 
        std::ptr::null_mut(), 
        0, 
        std::mem::transmute(funcaddr), 
        remotebase, 0, std::ptr::null_mut());

    }*/
    }
}*/


pub fn DllInject(prochandle:*mut c_void,dllpath:&str) -> *mut c_void{

    unsafe{

        let remotebase =VirtualAllocEx(prochandle, 
        std::ptr::null_mut(), 
        dllpath.len(), 0x1000, 0x40);


        WriteProcessMemory(prochandle, 
        remotebase, 
        dllpath.as_bytes().as_ptr() as *const c_void, 
        dllpath.len(), std::ptr::null_mut());

        let dllhandle =GetModuleHandleA("kernel32.dll\0".as_ptr() as *const i8);
        let funcaddress =    GetProcAddress(dllhandle,"LoadLibraryA\0".as_ptr() as *const i8);

        CreateRemoteThread(prochandle,
        std::ptr::null_mut(), 
        0, 
        Some(std::mem::transmute(funcaddress)),
         remotebase, 0, 
        std::ptr::null_mut());


            return remotebase;

    }


}



use std::collections;
use std::mem::*;
pub fn ParseExports64(prochandle:*mut c_void,baseaddress:*mut c_void) -> HashMap<String,i32>{

    unsafe{

        let mut exports:HashMap<String,i32> = HashMap::new();


        let mut dos:[u8;64] = [0;64];
        ReadProcessMemory(prochandle, 
        baseaddress, &mut dos as *mut u8 as *mut c_void, 
        64, std::ptr::null_mut());

        if dos[0]!=77 && dos[1]!=90{
            return exports;
        }

        let mut dosheader = IMAGE_DOS_HEADER::default();
        FillStructureFromArray(&mut dosheader, &dos);


        let mut nt:[u8;size_of::<IMAGE_NT_HEADERS64>()] = [0;size_of::<IMAGE_NT_HEADERS64>()];
        ReadProcessMemory(prochandle, 
        (baseaddress as isize + dosheader.e_lfanew as isize)as *const c_void, &mut nt as *mut u8 as *mut c_void, 
        size_of::<IMAGE_NT_HEADERS64>(), std::ptr::null_mut());
        
        let mut ntheader = IMAGE_NT_HEADERS64::default();
        FillStructureFromArray(&mut ntheader, &nt);


        if ntheader.OptionalHeader.ExportTable.Size==0{
            return exports;
        }

        let mut export = IMAGE_EXPORT_DIRECTORY::default();

        let mut exp:[u8;size_of::<IMAGE_EXPORT_DIRECTORY>()] = [0;size_of::<IMAGE_EXPORT_DIRECTORY>()];
        ReadProcessMemory(prochandle, 
        (baseaddress as isize + ntheader.OptionalHeader.ExportTable.VirtualAddress as isize)as *const c_void, &mut exp as *mut u8 as *mut c_void, 
        size_of::<IMAGE_EXPORT_DIRECTORY>(), std::ptr::null_mut());
            
        FillStructureFromArray(&mut export, &exp);

       // println!("{:x?}",export);


        let entptr =baseaddress as isize + export.AddressOfNames as isize;
        let eotptr =baseaddress as isize + export.AddressOfNameOrdinals as isize;
        let eatptr =baseaddress as isize + export.AddressOfFunctions as isize;



        for i in 0..export.NumberOfNames{

            let mut nameaddr:[u8;4] = [0;4];
            ReadProcessMemory(prochandle,
            (entptr + (i*4) as isize) as *const c_void, 
            nameaddr.as_mut_ptr() as *mut c_void, 4, std::ptr::null_mut());


            let nameoffset = i32::from_ne_bytes(nameaddr.try_into().unwrap());

            let funcname = ReadStringFromMemory(prochandle, (baseaddress as isize +nameoffset as isize )as *const c_void);
            

            let mut ordaddr:[u8;2] = [0;2];
            ReadProcessMemory(prochandle,
            (eotptr + (i*2) as isize) as *const c_void, 
            ordaddr.as_mut_ptr() as *mut c_void, 2, std::ptr::null_mut());

            let ordoffset = i32::from_ne_bytes(nameaddr.try_into().unwrap());
             
            


            let mut addresses:[u8;4] = [0;4];
            ReadProcessMemory(prochandle,
    (eatptr + (i*4) as isize) as *const c_void, 
            addresses.as_mut_ptr() as *mut c_void, 4, std::ptr::null_mut());
    
            let finaladdress = i32::from_ne_bytes(addresses.try_into().unwrap());

            exports.insert(funcname,finaladdress);

        }

        //println!("{:?}",exports);

        return exports;
    }



}



fn main() {
    
    let pid: u32 = 15108;
    let loadeddll = "tempdll.dll";


    unsafe{

        let prochandle = OpenProcess(0x001FFFFF, 0, pid);
        let magic:[u8;4];

        if prochandle.is_null() {
            panic!("OpenProcess failed with error: {}", GetLastError());
        }

        DllInject(prochandle, r#"D:\rust_practice\dlls\tempdll\target\release\tempdll.dll"#);
        

        let mut me =std::mem::MaybeUninit::<MODULEENTRY32>::uninit();
        me.assume_init().dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;

        let snaphandle = CreateToolhelp32Snapshot(TH32CS_SNAPALL, pid);

        let res= Module32First(snaphandle, me.as_mut_ptr());
        println!("result: {}",res);

        let modname =GetStringFromi8Array(&mut me.assume_init().szModule);

        println!("{} : {:x?}",modname,me.assume_init().modBaseAddr);
        
        let mut base:*mut c_void = 0 as *mut c_void ;
        let mut remotedllbase:*mut c_void = 0 as *mut c_void ;

        if modname.contains(".exe"){
            base = me.assume_init().modBaseAddr as *mut c_void;
        }

        /*if modname == loadeddll{
            remotedllbase = me.assume_init().modBaseAddr as *mut c_void;
        }*/

       loop{
        let mut me2 = std::mem::MaybeUninit::<MODULEENTRY32>::uninit();
        let res =Module32Next(snaphandle, me2.as_mut_ptr());
        if res!=1{
            break;
        }

        let modulename= GetStringFromi8Array(&mut me2.assume_init().szModule);
        println!("{} : {:x?}",modulename,me2.assume_init().modBaseAddr);


        if modulename ==loadeddll{
            remotedllbase = me2.assume_init().modBaseAddr as *mut c_void;
        }

        if modulename.contains(".exe"){
            base = me2.assume_init().modBaseAddr as *mut c_void;
            println!("base =====>{:x?}",base);
            //break;
        }

       }
       
       assert!(!base.is_null());
       assert!(!remotedllbase.is_null());
       
       println!("base -> {:x?}",base);
       println!("remote dllbase -> {:x?}",remotedllbase);
       
       ParseExports64(prochandle, remotedllbase);
       
       let mut t1:[u8;2] = [0;2];

       ReadProcessMemory(prochandle,
        remotedllbase, t1.as_mut_ptr() as *mut c_void,
         2, std::ptr::null_mut());
        println!("{:x?}",t1);


        //println!("{}",me.assume_init().hModule);
       
        let mut dos:[u8;64] = [0;64];

        ReadProcessMemory(prochandle, 
        base as *const c_void,
        dos.as_mut_ptr() as *mut c_void, 
        64, std::ptr::null_mut());


        let mut dosheader = IMAGE_DOS_HEADER::default();
        FillStructureFromArray(&mut dosheader, &dos);


        print!("{:x?}",dosheader.e_magic);

        let mut ntheader = IMAGE_NT_HEADERS64::default();
            let mut nt:[u8;std::mem::size_of::<IMAGE_NT_HEADERS64>()] = [0;std::mem::size_of::<IMAGE_NT_HEADERS64>()];

        ReadProcessMemory(prochandle, 
        (base as isize + dosheader.e_lfanew as isize) as *const c_void,
        nt.as_mut_ptr() as *mut c_void, 
        std::mem::size_of::<IMAGE_NT_HEADERS64>() , std::ptr::null_mut());    

            FillStructureFromArray(&mut ntheader, &nt);
            println!("{:x?}",ntheader);

         let importoffset = base as isize +ntheader.OptionalHeader.ImportTable.VirtualAddress as isize;

        let mut i=0;
            loop{

                let mut imp:[u8;std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>()] = [0;std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>()];
                
                ReadProcessMemory(prochandle, 
                (importoffset as isize+i*std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>() as isize) as *const c_void,
                imp.as_mut_ptr() as *mut c_void, 
                 std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>() , std::ptr::null_mut());    
            
                let mut import = IMAGE_IMPORT_DESCRIPTOR::default();
                //FillStructureFromMemory(&mut import, (importoffset+(i*std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>() as isize)) as *const c_void, prochandle);
                FillStructureFromArray(&mut import, &imp);

                if import.Name == 0{
                    break;
                }

                let dllname =ReadStringFromMemory(prochandle, (base as isize+import.Name as isize) as *const c_void);
                    println!("dll name: {}",dllname);
               
                if dllname.trim_end_matches('\0')=="USER32.dll"{
                    println!("{}",dllname);

                    /* */ let firsthunkptr = (base as isize + import.Characteristics_or_OriginalFirstThunk as isize) as *mut c_void;
                    
                    let mut j=0;
                    loop{
                        
                    let mut originalthunk:[u8;std::mem::size_of::<isize>()] = [0;std::mem::size_of::<isize>()];
                    
                    ReadProcessMemory(prochandle,
                    (firsthunkptr as isize +(j*std::mem::size_of::<isize>() as isize) ) as *const c_void, 
                    originalthunk.as_mut_ptr() as *mut c_void, originalthunk.len(),
                    std::ptr::null_mut());

                    let thunkoffset = usize::from_ne_bytes(originalthunk);
                    //println!("{:x?}",thunkoffset);

                    if thunkoffset==0{
                        break;
                    }

                    let funcname =ReadStringFromMemory(prochandle,(base as isize + thunkoffset as isize +2)as *const c_void);
                        println!("funcname: {}",funcname);


                    let addr =(base as isize+import.FirstThunk as isize+(j*std::mem::size_of::<isize>() as isize)) as *const c_void;
                    let mut address:[u8;std::mem::size_of::<isize>()] = [0;std::mem::size_of::<isize>()];

                     ReadProcessMemory(prochandle, 
                    addr,
                    address.as_mut_ptr() as *mut c_void, 
                    address.len(), std::ptr::null_mut());


                    let finaladdress = usize::from_ne_bytes(address);
                        println!( "final address{:x?}",finaladdress);
                        println!("final {:x?}",address);


                       let exports = ParseExports64(prochandle, remotedllbase);
                        if exports.contains_key("messageboxclone") && 
                        funcname=="MessageBoxA"{
                            let mut funcaddr =*exports.get("messageboxclone").unwrap();
                            
                            println!("exports: {:x?}",exports);
                            println!("messageboxclone: {:x?}",funcaddr);
                            funcaddr = remotedllbase as i32+ funcaddr ;

                           println!("messageboxclone after adding base: {:x?}",funcaddr);

                            let funcoffset2:[u8;4] =funcaddr.to_ne_bytes();


                            let mut oldprotect = 0;
                            VirtualProtectEx(prochandle, addr as *mut c_void, 4, 0x40, &mut oldprotect);
                            println!("old protection: {}",oldprotect);
                            println!("last error : {}",GetLastError());
                            WriteProcessMemory(prochandle, 
                            addr as *mut c_void, 
                            funcoffset2.as_ptr() as *const c_void, 
                            funcoffset2.len(), std::ptr::null_mut());

                            println!("last error : {}",GetLastError());

                            ReadProcessMemory(prochandle, 
                                addr,
                                address.as_mut_ptr() as *mut c_void, 
                                address.len(), std::ptr::null_mut());

                                println!("after writing: {:x?}",address);

                        }



                    j+=1;

                    }
                
                    }

                i+=1;
                
            }


        CloseHandle(prochandle);

    }
}









#[derive(Clone, Default, Debug)]
#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    Name: [u8; 8],
    VirtualSize: u32,
    VirtualAddress: u32,
    SizeOfRawData: u32,
    PointerToRawData: u32,
    PointerToRelocations: u32,
    PointerToLinenumbers: u32,
    NumberOfRelocations: u16,
    NumberOfLinenumbers: u16,
    Characteristics: u32,
}

impl IMAGE_SECTION_HEADER {
    fn getsecname(&mut self) -> String {
        String::from_utf8_lossy(&self.Name).to_string()
    }
}

#[repr(C)]
pub union chars_or_originalfirstthunk {
    Characteristics: u32,
    OriginalFirstThunk: u32,
}

#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct IMAGE_IMPORT_DESCRIPTOR {
    Characteristics_or_OriginalFirstThunk: u32,

    TimeDateStamp: u32,

    ForwarderChain: u32,

    Name: u32,

    FirstThunk: u32,
}

#[repr(C)]
pub union IMAGE_THUNK_DATA32 {
    pub ForwarderString: u32,

    pub Function: u32,

    pub Ordinal: u32,

    pub AddressOfData: u32,
}

#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFnctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,    // RVA from base of image
    pub AddressOfNames: u32,        // RVA from base of image
    pub AddressOfNameOrdinals: u32, // RVA from base of image
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    Magic: u16,

    MajorLinkerVersion: u8,

    MinorLinkerVersion: u8,

    SizeOfCode: u32,

    SizeOfInitializedData: u32,

    SizeOfUninitializedData: u32,

    AddressOfEntryPoint: u32,

    BaseOfCode: u32,

    ImageBase: i64,

    SectionAlignment: u32,

    FileAlignment: u32,

    MajorOperatingSystemVersion: u16,

    MinorOperatingSystemVersion: u16,

    MajorImageVersion: u16,

    MinorImageVersion: u16,

    MajorSubsystemVersion: u16,

    MinorSubsystemVersion: u16,

    Win32VersionValue: u32,

    SizeOfImage: u32,

    SizeOfHeaders: u32,

    CheckSum: u32,

    Subsystem: u16,

    DllCharacteristics: u16,

    SizeOfStackReserve: u64,

    SizeOfStackCommit: u64,

    SizeOfHeapReserve: u64,

    SizeOfHeapCommit: u64,

    LoaderFlags: u32,

    NumberOfRvaAndSizes: u32,

    ExportTable: IMAGE_DATA_DIRECTORY,

    ImportTable: IMAGE_DATA_DIRECTORY,

    ResourceTable: IMAGE_DATA_DIRECTORY,

    ExceptionTable: IMAGE_DATA_DIRECTORY,

    CertificateTable: IMAGE_DATA_DIRECTORY,

    BaseRelocationTable: IMAGE_DATA_DIRECTORY,

    Debug: IMAGE_DATA_DIRECTORY,

    Architecture: IMAGE_DATA_DIRECTORY,

    GlobalPtr: IMAGE_DATA_DIRECTORY,

    TLSTable: IMAGE_DATA_DIRECTORY,
    LoadConfigTable: IMAGE_DATA_DIRECTORY,
    BoundImport: IMAGE_DATA_DIRECTORY,

    IAT: IMAGE_DATA_DIRECTORY,

    DelayImportDescriptor: IMAGE_DATA_DIRECTORY,
    CLRRuntimeHeader: IMAGE_DATA_DIRECTORY,

    Reserved: IMAGE_DATA_DIRECTORY,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER32 {
    Magic: u16,

    MajorLinkerVersion: u8,

    MinorLinkerVersion: u8,

    SizeOfCode: u32,

    SizeOfInitializedData: u32,

    SizeOfUninitializedData: u32,

    AddressOfEntryPoint: u32,

    BaseOfCode: u32,

    // PE32 contains this additional field
    BaseOfData: u32,

    ImageBase: u32,

    SectionAlignment: u32,

    FileAlignment: u32,

    MajorOperatingSystemVersion: u16,

    MinorOperatingSystemVersion: u16,

    MajorImageVersion: u16,

    MinorImageVersion: u16,

    MajorSubsystemVersion: u16,

    MinorSubsystemVersion: u16,

    Win32VersionValue: u32,

    SizeOfImage: u32,

    SizeOfHeaders: u32,

    CheckSum: u32,

    Subsystem: u32,

    DllCharacteristics: u16,

    SizeOfStackReserve: u32,

    SizeOfStackCommit: u32,

    SizeOfHeapReserve: u32,

    SizeOfHeapCommit: u32,

    LoaderFlags: u32,

    NumberOfRvaAndSizes: u32,

    ExportTable: IMAGE_DATA_DIRECTORY,

    ImportTable: IMAGE_DATA_DIRECTORY,

    ResourceTable: IMAGE_DATA_DIRECTORY,

    ExceptionTable: IMAGE_DATA_DIRECTORY,

    CertificateTable: IMAGE_DATA_DIRECTORY,

    BaseRelocationTable: IMAGE_DATA_DIRECTORY,

    Debug: IMAGE_DATA_DIRECTORY,

    Architecture: IMAGE_DATA_DIRECTORY,

    GlobalPtr: IMAGE_DATA_DIRECTORY,

    TLSTable: IMAGE_DATA_DIRECTORY,
    LoadConfigTable: IMAGE_DATA_DIRECTORY,
    BoundImport: IMAGE_DATA_DIRECTORY,

    IAT: IMAGE_DATA_DIRECTORY,

    DelayImportDescriptor: IMAGE_DATA_DIRECTORY,
    CLRRuntimeHeader: IMAGE_DATA_DIRECTORY,

    Reserved: IMAGE_DATA_DIRECTORY,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    VirtualAddress: u32,
    Size: u32,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_NT_HEADERS32 {
    Signature: u32,

    FileHeader: IMAGE_FILE_HEADER,

    OptionalHeader: IMAGE_OPTIONAL_HEADER32,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    Signature: u32,

    FileHeader: IMAGE_FILE_HEADER,

    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]

pub struct IMAGE_DOS_HEADER {
    e_magic: [u8; 2],  // Magic number
    e_cblp: u16,       // Bytes on last page of file
    e_cp: u16,         // Pages in file
    e_crlc: u16,       // Relocations
    e_cparhdr: u16,    // Size of header in paragraphs
    e_minalloc: u16,   // Minimum extra paragraphs needed
    e_maxalloc: u16,   // Maximum extra paragraphs needed
    e_ss: u16,         // Initial (relative) SS value
    e_sp: u16,         // Initial SP value
    e_csum: u16,       // Checksum
    e_ip: u16,         // Initial IP value
    e_cs: u16,         // Initial (relative) CS value
    e_lfarlc: u16,     // File address of relocation table
    e_ovno: u16,       // Overlay number
    e_res1: [u16; 4],  // Reserved words
    e_oemid: u16,      // OEM identifier (for e_oeminfo)
    e_oeminfo: u16,    // OEM information, e_oemid specific
    e_res2: [u16; 10], // Reserved words
    e_lfanew: i32,     // File address of new exe header
}







