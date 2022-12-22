
use winapi::{um::winuser::*, shared::windef::HWND__};
use winapi::ctypes::*;
use winapi::um::memoryapi::*;
use winapi::um::libloaderapi::*;
use winapi::um::processthreadsapi::*;
use winapi::shared::ntdef::{HRESULT, NTSTATUS, NT_SUCCESS, NULL};
use windows::Win32::System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION;

use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use ntapi::ntexapi::*;
use winapi::ctypes::*;
use winapi::um::winnt::*;
use winapi::shared::minwindef::*;
use std::collections::HashMap;
use std::fmt::Write;
use std::hash::Hash;
use std::io::Read;

use winapi::shared::minwindef::HINSTANCE;

use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::*;
use winapi::um::memoryapi::*;
use winapi::um::libloaderapi::*;
use winapi::um::winnt::IMAGE_IMPORT_BY_NAME;
use winapi::um::winuser::*;
use winapi::um::winuser::MessageBoxA;
use winapi::ctypes::*;
use winapi::um::tlhelp32::*;

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




#[no_mangle]
pub unsafe extern "C"  fn messageboxclone(hwnd:*mut HWND__,
    lptext:*const i8,lptitle:*const i8,boxtype:u32) ->i32 {
    

         /*WriteProcessMemory(prochandle1, 
        firstthunkaddress as *mut c_void, 
        originaladdress.to_ne_bytes().as_ptr() as *const c_void,
         originaladdress.to_ne_bytes().len(), std::ptr::null_mut());
                */
            
        let temp = ReadStringFromMemory(GetCurrentProcess(), lptext as *const c_void);
        println!("lp text: {}",
    ReadStringFromMemory(GetCurrentProcess(), lptext as *const c_void));

        if temp=="hello world"{

    let res =MessageBoxA(std::ptr::null_mut(),
    "pwned it!\0".as_ptr() as *const i8,
    "WORKED\0".as_ptr() as *const i8,0   );
    return res;
        }

        else{

            return MessageBoxA(std::ptr::null_mut(),
            lptext,lptitle,boxtype);
        

        }

            let mut temp:[u8;size_of::<isize>()] = [0;size_of::<isize>()];


   /* let res2 =WriteProcessMemory(prochandle1, 
        firstthunkaddress as *mut c_void, 
        temp.as_ptr() as *const c_void, 
        temp.len(), std::ptr::null_mut());
    */ 

   // return res;
    
}



#[no_mangle]
pub unsafe extern "C" fn test2(sysinfo: SYSTEM_INFORMATION_CLASS,
    baseaddress:*mut c_void,
    infolength: u32,
    outinfolength: *mut u32) -> i32{


       // return NtQuerySystemInformation(sysinfo , baseaddress, infolength, outinfolength);

        if sysinfo==5{

            /*MessageBoxA(std::ptr::null_mut(),
        "calling SYS_PROCESS_INFO\0".as_ptr() as *const i8,
        "hooked\0".as_ptr() as *const i8,0   );*/

            return NtQuerySystemInformation(sysinfo , baseaddress, infolength, outinfolength);
        

        }
        

        return NtQuerySystemInformation(sysinfo , baseaddress, infolength, outinfolength);
        
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




use std::collections::*;
use std::mem::*;
pub fn ParseImports64(prochandle: *mut c_void,baseaddress: *mut c_void) -> HashMap<String,Vec<HashMap<String,HashMap<String,i64>>>>{
    // dll : {funcname : {firstthunk: addr1,addressrva: addr2}}

    let mut imports:HashMap<String,Vec<HashMap<String,HashMap<String,i64>>>> = HashMap::new();

    unsafe{


        let mut dos:[u8;64] = [0;64];
        ReadProcessMemory(prochandle, 
        baseaddress, &mut dos as *mut u8 as *mut c_void, 
        64, std::ptr::null_mut());

        if dos[0]!=77 && dos[1]!=90{
            return imports;
        }

        let mut dosheader = IMAGE_DOS_HEADER::default();
        FillStructureFromArray(&mut dosheader, &dos);


        let mut nt:[u8;size_of::<IMAGE_NT_HEADERS64>()] = [0;size_of::<IMAGE_NT_HEADERS64>()];
        ReadProcessMemory(prochandle, 
        (baseaddress as isize + dosheader.e_lfanew as isize)as *const c_void, &mut nt as *mut u8 as *mut c_void, 
        size_of::<IMAGE_NT_HEADERS64>(), std::ptr::null_mut());
        
        let mut ntheader = IMAGE_NT_HEADERS64::default();
        FillStructureFromArray(&mut ntheader, &nt);


        if ntheader.OptionalHeader.ImportTable.Size==0{
            return imports;
        }

        let mut importptr = baseaddress as isize + ntheader.OptionalHeader.ImportTable.VirtualAddress as isize;

        let mut i =0;

        loop{

            let mut import:[u8;size_of::<IMAGE_IMPORT_DESCRIPTOR>()] = [0;size_of::<IMAGE_IMPORT_DESCRIPTOR>()];
            ReadProcessMemory(prochandle, 
            (importptr + i*size_of::<IMAGE_IMPORT_DESCRIPTOR>() as isize) as *const c_void, 
            import.as_mut_ptr() as *mut c_void, 
            import.len(), std::ptr::null_mut());

            let mut firstimport = IMAGE_IMPORT_DESCRIPTOR::default();
            FillStructureFromArray(&mut firstimport, &import);

            if firstimport.Name == 0{
                break;
            }

            let dllname =ReadStringFromMemory(prochandle, (baseaddress as isize + firstimport.Name as isize) as *const c_void);
            //imports.insert(dllname, std::ptr::null());

            let mut v:Vec<HashMap<String,HashMap<String,i64>>>= Vec::new();

            let originalthunkptr = baseaddress as isize + firstimport.Characteristics_or_OriginalFirstThunk as isize;
            let firstthunkptr = baseaddress as isize + firstimport.FirstThunk as isize;
            let mut j=0;

            loop{

                let mut nameaddr:[u8;8] = [0;8];
                ReadProcessMemory(prochandle, 
                (originalthunkptr + j*8) as *const c_void, 
                nameaddr.as_mut_ptr() as *mut c_void, 
                nameaddr.len(), std::ptr::null_mut());
        
                let nameoffset = isize::from_ne_bytes(nameaddr.try_into().unwrap());
                
                if nameoffset ==0{
                    break;
                }


                let funcname =ReadStringFromMemory(prochandle, (baseaddress as isize + nameoffset  as isize +2) as *const c_void);
                let mut funcdict:HashMap<String,HashMap<String,i64>> = HashMap::new();
                let mut addressdict:HashMap<String,i64> = HashMap::new();

                addressdict.insert("firstthunk".to_string(), firstthunkptr as i64 + (j*8) as i64);

                let mut funcaddress:[u8;8] = [0;8];
                ReadProcessMemory(prochandle, 
                (firstthunkptr + j*8) as *const c_void, 
                funcaddress.as_mut_ptr() as *mut c_void, 
                funcaddress.len(), std::ptr::null_mut());
            
                addressdict.insert("addressrva".to_string(), i64::from_ne_bytes(funcaddress.try_into().unwrap()));

                    funcdict.insert(funcname,addressdict);
                    v.push(funcdict);
                    j+=1;
            }
            imports.insert(dllname,v);

            i+=1 ;
        }


        return imports;

    }

}




static mut originaladdress:isize =0;
static mut firstthunkaddress:isize =0;
static mut prochandle1: *mut c_void = 0 as *mut c_void;

#[no_mangle]
pub unsafe extern "stdcall" fn DllMain(
    handle:HINSTANCE,
    reason: u32,
    reserved:*mut c_void
) -> u32{

    if reason ==1{


        let targetdll = "ntdll.dll";
        let legitfunctiontohook = "NtQuerySystemInformation";
        let ourmaliciousfunction = "test2";

        
        let procbase =GetModuleHandleA(std::ptr::null_mut());

        let dllbase =GetModuleHandleA("tempdll.dll".as_ptr() as *const i8);

        let allimports = ParseImports64(procbase as *mut c_void, procbase as *mut c_void);

        
        let pid =GetCurrentProcessId();
         prochandle1 = OpenProcess(0x001FFFFF, 0, pid);


        let allimports= ParseImports64(prochandle1, procbase as *mut c_void);
        let dllexports = ParseExports64(prochandle1, dllbase as *mut c_void);


        let legitdllimports =allimports.get(targetdll).unwrap();

        let mut funcinfo:HashMap<String, HashMap<String, i64>> = HashMap::new();
        for i in 0..legitdllimports.len(){
            let keys =legitdllimports[i].keys().collect::<Vec<&String>>();
            if keys[0] == legitfunctiontohook{
                println!("{:x?}",legitdllimports[i]);
                funcinfo = legitdllimports[i].clone();
            }
        }

        //let mut firstthunkaddress:isize =0;
        

        for i in funcinfo.values(){
            if i.contains_key("firstthunk"){
                firstthunkaddress = *i.get("firstthunk").unwrap() as isize;
            }
            if i.contains_key("addressrva"){
                originaladdress = *i.get("addressrva").unwrap() as isize;
            }
        }   

        println!("First thunk address: {:x?}",firstthunkaddress);
        println!("address rva: {:x?}",originaladdress);

        let mut maladdress: isize = 0;

        for (i,j) in dllexports.iter(){
            if i==ourmaliciousfunction{
                maladdress = *j as isize;
            }
        }
        
        let mut oldprotect = 0;
        let res =VirtualProtectEx(prochandle1,
            firstthunkaddress as *mut c_void, 4, 0x40, &mut oldprotect);
             
            println!("virtualprotectex res: {}",res);
            
        
        maladdress = dllbase as isize+ maladdress;

        println!("dllbase :{:x?}",dllbase);
        println!("maladdress: {:x?}",maladdress);

        let mut temp:[u8;size_of::<isize>()] = maladdress.to_ne_bytes();

                          
        println!("temp: {:x?}",temp);


            let mut temp2:[u8;size_of::<isize>()] = [0;size_of::<isize>()];
            ReadProcessMemory(prochandle1, 
                firstthunkaddress as *const c_void, 
                temp2.as_mut_ptr() as *mut c_void, 
                temp2.len(), std::ptr::null_mut());
                    
                println!("before writing, firstthunkaddress: {:x?}",temp2);

        let res2 =WriteProcessMemory(prochandle1, 
    firstthunkaddress as *mut c_void, 
    temp.as_ptr() as *const c_void, 
    temp.len(), std::ptr::null_mut());

        println!("writeprocessmem result: {}",res2);        

        ReadProcessMemory(prochandle1, 
        firstthunkaddress as *const c_void, 
        temp.as_mut_ptr() as *mut c_void, 
        temp.len(), std::ptr::null_mut());
            
            println!("after written, firstthunk: {:x?}",temp);

        /*MessageBoxA(std::ptr::null_mut(),
        format!("{:x?}",dllexports).as_ptr() as *const i8,
    "hooked\0".as_ptr() as *const i8,0   );*/

            

        CloseHandle(prochandle1);
    
    return 1 ;
    
}
    if reason ==0{
        1;
    }
    return 0;

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



