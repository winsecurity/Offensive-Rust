
use std::fmt::Write;
use std::io::Read;
use std::mem::transmute;
use winapi::ctypes::{c_schar,c_char};
use winapi::shared::basetsd::DWORD32;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::shared::ntdef::ULONGLONG;
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree, WriteProcessMemory};
use winapi::um::processthreadsapi::{CreateThread,GetCurrentProcess};
use winapi::um::winnt::{WCHAR, IMAGE_IMPORT_BY_NAME, IMAGE_THUNK_DATA64, IMAGE_THUNK_DATA64_u1};
use winapi::{ctypes::c_void, um::memoryapi::ReadProcessMemory};
use winapi::um::libloaderapi::{LoadLibraryW,GetProcAddress, LoadLibraryA};
use winapi::um::errhandlingapi::{GetLastError};
use std::alloc::{alloc, Layout};
use widestring;
use std::ffi::{CString,CStr};


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



pub fn ReflectiveLoader64(phandle:*mut c_void,buffer:Vec<u8>){
    unsafe{

        
   


        let headerssize =GetHeadersSize(&buffer);
        let imagesize = GetImageSize(&buffer);
    
          //  let phandle = GetCurrentProcess();
            let baseptr =VirtualAlloc(std::ptr::null_mut(), 
            imagesize, 0x1000, 0x40);
    
    
            WriteProcessMemory(phandle, 
            baseptr, 
            buffer.as_ptr() as *const c_void,
             headerssize, std::ptr::null_mut());
    
            let mut dosheader = IMAGE_DOS_HEADER::default();
            FillStructureFromArray(&mut dosheader, &buffer);
    
            //println!("magic: {:x?}",dosheader.e_magic);
            //println!("elfa new: {:x?}",dosheader.e_lfanew);
    
            let mut ntheader = IMAGE_NT_HEADERS64::default();
            FillStructureFromMemory(&mut ntheader, 
            (baseptr as isize + dosheader.e_lfanew as isize) as *const c_void, phandle);
    
    
            ////println!("{:#x?}",ntheader);
    
    
            let mut sections:Vec<IMAGE_SECTION_HEADER> = vec![IMAGE_SECTION_HEADER::default();ntheader.FileHeader.NumberOfSections as usize];
    
            for i in 0..sections.len(){
    
                FillStructureFromMemory(&mut sections[i],
                ((baseptr as usize + dosheader.e_lfanew as usize + std::mem::size_of_val(&ntheader) as usize + (i*std::mem::size_of::<IMAGE_SECTION_HEADER>()) as usize)) as *const c_void,
                 phandle);
    
    
                 //println!("{}",GetStringFromu8Array(&mut sections[i].Name));
    
    
                    let temp:Vec<u8> = buffer[sections[i].PointerToRawData as usize..(sections[i].PointerToRawData as usize+sections[i].SizeOfRawData as usize)].to_vec();
    
    
                    WriteProcessMemory(phandle,
                     (baseptr as usize+sections[i].VirtualAddress as usize) as *mut c_void,
                      temp.as_ptr() as *const c_void, 
                      sections[i].SizeOfRawData as usize, std::ptr::null_mut());
    
    
    
    
            }
            
            
            if ntheader.OptionalHeader.ImportTable.Size > 0{
    
                let mut ogfirstthunkptr = baseptr as usize + ntheader.OptionalHeader.ImportTable.VirtualAddress as usize;
    
                while true {
    
                    
                    let mut import = IMAGE_IMPORT_DESCRIPTOR::default();
    
                    FillStructureFromMemory(&mut import, 
                    ogfirstthunkptr as *const c_void, phandle);
    
                
                    if import.Name ==0 && import.FirstThunk ==0{
                        break;
                    }
    
                    let dllname = ReadStringFromMemory(
                    (baseptr as usize + import.Name as usize) as *const u8,
                     phandle);
    
                     //println!("DLL Name: {}",dllname);
                     let dllhandle =LoadLibraryA(dllname.as_bytes().as_ptr() as *const i8);
    
                    let mut thunkptr =  baseptr as usize + import.Characteristics_or_OriginalFirstThunk as usize;
    
                        let mut i = 0;
    
                    while true{
    
    
    
                        let mut thunkdata = MY_IMAGE_THUNK_DATA64::default();
    
                        FillStructureFromMemory(&mut thunkdata,(thunkptr as usize)as *const c_void, phandle);
    
                        if thunkdata.Address == [0;8] && 
                        u64::from_ne_bytes(thunkdata.Address.try_into().unwrap())<0x8000000000000000
                        {
                            break;
                        }
    
                        ////println!("thunkdata: {:x?}",thunkdata); 
                        let offset = u64::from_ne_bytes(thunkdata.Address.try_into().unwrap());
    
                        let funcname = ReadStringFromMemory(
                            (baseptr as usize+ offset as usize+ 2) as *const u8, phandle);
    
                            //println!("function name: {}",funcname);
    
                            if funcname!=""{
                            let funcaddress =GetProcAddress(dllhandle, funcname.as_bytes().as_ptr() as *const i8);
    
                            let finalvalue =i64::to_ne_bytes(funcaddress as i64);
    
                            WriteProcessMemory(phandle, 
                                
                            (baseptr as usize + import.FirstThunk as usize +(i*8) ) as *mut c_void,
                            finalvalue.as_ptr() as *const c_void ,
                             finalvalue.len(), std::ptr::null_mut());
                            }
                                i+=1;
    
                        thunkptr += 8;
    
                    }
    
                    ogfirstthunkptr += std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
    
    
                }
    
    
            }
    
    
    
    
            // fixing base relocations
    
            if ntheader.OptionalHeader.BaseRelocationTable.Size > 0{
    
              let diffaddress = baseptr as usize - ntheader.OptionalHeader.ImageBase as usize;
                let mut relocptr = baseptr as usize + ntheader.OptionalHeader.BaseRelocationTable.VirtualAddress as usize;
    
                while true {
                    
                    let mut reloc1 = MY_IMAGE_BASE_RELOCATION::default();
    
    
                    FillStructureFromMemory(&mut reloc1, relocptr as *const c_void, phandle);
    
                    if reloc1.SizeofBlock ==0 {
                        break;
                    }
    
                    //println!("page rva: {:x?}",reloc1.VirtualAddress);
                    //println!("block size: {:x?}",reloc1.SizeofBlock);
    
    
                    let  entries =(reloc1.SizeofBlock-8) /2 ;
                    
                    //println!("entries: {:x?}",entries);
    
                    
    
                    for i in 0..entries{
    
    
                        let mut relocoffset:[u8;2] = [0;2];
    
                        ReadProcessMemory(phandle,
                        ( relocptr +8+(i*2) as usize)as *const c_void, 
                        relocoffset.as_mut_ptr() as *mut c_void, 
                        2, std::ptr::null_mut());
    
                        let temp = u16::from_ne_bytes(relocoffset.try_into().unwrap());
    
                            ////println!("{:x?}",temp&0x0fff);
    
                            let type1 = temp >> 12;
                        if type1==0xA{
    
                            // 1&0=0  0&0=0
                        let finaladdress = baseptr as usize + reloc1.VirtualAddress as usize + (temp&0x0fff) as usize;
    
                         let mut ogaddress:[u8;8] = [0;8];
                         
                         ReadProcessMemory(phandle, 
                         finaladdress as *const c_void, 
                         ogaddress.as_mut_ptr() as *mut c_void, 
                         8, std::ptr::null_mut());
    
    
                        let fixedaddress= isize::from_ne_bytes(ogaddress.try_into().unwrap()) + diffaddress as isize;
    
    
                            WriteProcessMemory(phandle, 
                            finaladdress as *mut c_void, 
                            fixedaddress.to_ne_bytes().as_ptr() as *const c_void, 
                            8, std::ptr::null_mut());
                            }
                    }
    
    
                    relocptr += reloc1.SizeofBlock as usize;
    
                }
    
    
            }
    
    
    
    
    
    
    
            let mut threadid =0;
            
    
            let threadres =CreateThread(std::ptr::null_mut(), 0
            , 
            Some(transmute((baseptr as usize + ntheader.OptionalHeader.AddressOfEntryPoint as usize) as *mut c_void)),
             std::ptr::null_mut(), 0, std::ptr::null_mut());
    
    
            WaitForSingleObject(threadres, 10000);
    
    
    
    
    
            VirtualFree(baseptr, 0, 0x00008000);
    
        }


}



fn main() {
    
    

    let mut buffer:Vec<u8> = Vec::new();
    //
    let mut fd =File::open(r#"D:\red teaming tools\calc2.exe"#).unwrap();
    

    fd.read_to_end(&mut buffer);

    unsafe{
    ReflectiveLoader64(GetCurrentProcess(), buffer.clone());
    }

}



#[derive(Debug,Clone,Default)]
pub struct MY_IMAGE_BASE_RELOCATION{
    VirtualAddress: u32,
    SizeofBlock: u32

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
