use std::collections::HashMap;
use std::fs::*;
use std::io::{BufReader, Read};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::psapi::EnumProcesses;
use winapi::um::winnt::*;
use winapi::ctypes::*;
use winapi::um::libloaderapi::*;
use winapi::um::synchapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::memoryapi::*;
use winapi::um::winuser::{FindWindowW, GetWindowTextW};

struct peparse64{
    path: String,
    bytecontent: Vec<u8>
}


// associated functions
impl peparse64{

    /// Takes the file path as parameter and 
    /// initiates the structure.
    fn parsefile(pepath: String) -> peparse64{
        peparse64{path:pepath, bytecontent:Vec::new()}
    }

    /// Takes the byte array as parameter and
    /// initiates the structure.
    fn parsebytearray( bytearray: Vec<u8>) -> peparse64{
        peparse64{path:"".to_string(),bytecontent:bytearray}
    }

    
}

impl peparse64{

    fn rvatooffset(&self,x:u32) -> Result<u32,String>{
        //println!("{:x?}",x);
        let sections = self.getsectionheaders().unwrap();
        let mut fileoffset: u32 = 0;
        for i in 0..sections.len(){
            if x>=sections[i].VirtualAddress && x < (sections[i].VirtualAddress + sections[i].VirtualSize){
                fileoffset = x - sections[i].VirtualAddress;
                fileoffset += sections[i].PointerToRawData;
                return Ok(fileoffset);
            }
        }
        Err("RVA not found in any of the sections".to_string())

    }

    fn ispefile(&mut self) -> bool {
        if self.path!= ""{
            let f = File::open(&self.path);
            let mut bufferreader = BufReader::new(f.unwrap());
            let mut pebuffer:Vec<u8> = Vec::new();
            
            //self.bytecontent = pebuffer;

            bufferreader.read_to_end(&mut pebuffer);
            self.bytecontent = pebuffer;
        }
            let pebuffer = self.bytecontent.clone();
            if pebuffer[0]!=0x4d && pebuffer[1]!=0x5a{
                return false;
            }

            let elfanew = i32::from_ne_bytes(pebuffer[60..64].try_into().unwrap()) as usize;

            if pebuffer[elfanew+4]==0x64 {
                if pebuffer[elfanew+4+1] == 0x86 {
                    
                    return true;
                }
            }

            
            /*if i16::from_le_bytes(pebuffer[0..2].try_into().unwrap())==0x5a4d{
                println!("valid pe file");
                println!("{:x?}",i16::from_ne_bytes(pebuffer[(i32::from_ne_bytes(pebuffer[60..64].try_into().unwrap())) as usize .. ((i32::from_ne_bytes(pebuffer[60..64].try_into().unwrap()))+2) as usize].try_into().unwrap()));
                /*if i16::from_ne_bytes(pebuffer[(i16::from_ne_bytes(pebuffer[60..64].try_into().unwrap())) as usize .. 2].try_into().unwrap())==0x8664{
                    println!("valid machine value");
                }*/
            }*/
            
        

        false

    }
    

    fn getdosheader(&self) -> Result<IMAGE_DOS_HEADER,String> {

        //println!("bytecontent length: {}",self.bytecontent.len());
        if self.bytecontent.len()<64{
            return Err("not enough content".to_string());
        }
        
        unsafe{
            let mut dosheader = std::mem::zeroed::<IMAGE_DOS_HEADER>();
            dosheader = *(self.bytecontent.as_ptr() as *const IMAGE_DOS_HEADER);
            //let byteswritten = FillStructureFromArray(&mut dosheader, &self.bytecontent[0..64]);
            //println!("{}",byteswritten);
            return Ok(dosheader);
        }

        //Err("cannot parse".to_string()) 
    }

    fn getntheader(&self) -> Result<IMAGE_NT_HEADERS64,String>{

        let dosheader = self.getdosheader().unwrap();
        unsafe{
            let ntheader = *(self.bytecontent[dosheader.e_lfanew as usize..].as_ptr() as *const IMAGE_NT_HEADERS64);
            return Ok(ntheader);
        }

        Err("cannot parse".to_string())

    }

    fn getsectionheaders(&self) -> Result<Vec<IMAGE_SECTION_HEADER>,String>{

        let dosheader = self.getdosheader().unwrap();
        let ntheader = self.getntheader().unwrap();
        let mut sections:Vec<IMAGE_SECTION_HEADER> = Vec::new();

        for i in 0..ntheader.FileHeader.NumberOfSections{
            let base = (dosheader.e_lfanew + 24 + ntheader.FileHeader.SizeOfOptionalHeader as i32) ;
            let temp = (base as usize + (i as usize*std::mem::size_of::<IMAGE_SECTION_HEADER>() as usize) ) as usize;
            unsafe{
            let sectionheader = *(self.bytecontent[temp..temp+ (std::mem::size_of::<IMAGE_SECTION_HEADER>()) as usize].as_ptr() as *const IMAGE_SECTION_HEADER);
            sections.push(sectionheader);
            }
        }

        return Ok(sections);
        Err("cannot parse".to_string())

    }

    fn getexportdirectory(&self) -> Result<IMAGE_EXPORT_DIRECTORY,String> {
        
        let ntheader = self.getntheader().unwrap();
        let sections = self.getsectionheaders().unwrap();
        let mut offset = 0;
        offset = self.rvatooffset(ntheader.OptionalHeader.DataDirectory[0].VirtualAddress).unwrap();
        //println!("inside func: {:x?}",ntheader.OptionalHeader.DataDirectory[0].VirtualAddress);
        unsafe{

            //ntheader.OptionalHeader.DataDirectory[0].VirtualAddress as usize
            let exporttable = *(self.bytecontent[offset as usize..
                 /*(ntheader.OptionalHeader.DataDirectory[0].VirtualAddress as usize)+(std::mem::size_of::<IMAGE_EXPORT_DIRECTORY>())*/].as_ptr() as *const IMAGE_EXPORT_DIRECTORY);
            return Ok(exporttable);
        }
    }

    fn getexports(&self) -> HashMap<String,Vec<HashMap<String,u32>>>{

        let mut exports:HashMap<String,Vec<HashMap<String,u32>>> = HashMap::new();
        let mut rvas: Vec<HashMap<String,u32>> = Vec::new();
        let sections = self.getsectionheaders().unwrap();
        
        let exporttable = self.getexportdirectory().unwrap();

        let mut nameoffset = 0;
        let mut eatoffset = 0;
        let mut eotoffset = 0;
        let mut entoffset = 0;

        for i in 0..sections.len(){
            if exporttable.Name > sections[i].VirtualAddress &&
                exporttable.Name < (sections[i].VirtualAddress + sections[i].VirtualSize){
                    nameoffset = exporttable.Name - sections[i].VirtualAddress;
                    nameoffset += sections[i].PointerToRawData;

                    eatoffset = exporttable.AddressOfFunctions -sections[i].VirtualAddress;
                    eatoffset += sections[i].PointerToRawData;

                    eotoffset = exporttable.AddressOfNameOrdinals -sections[i].VirtualAddress;
                    eotoffset += sections[i].PointerToRawData;

                    entoffset = exporttable.AddressOfNames -sections[i].VirtualAddress;
                    entoffset += sections[i].PointerToRawData;

                    break;
                }
            


            
        }

        //println!("Name offset: {:x?}",nameoffset);
        let mut dllname = String::new();
        unsafe{
        dllname = ReadStringFromMemory(GetCurrentProcess(), self.bytecontent[nameoffset as usize..].as_ptr() as *const c_void);
        //println!("dllname: {}",dllname);
        //exports.insert(dllname, Vec::new());
        }
        
        //println!("EAT Offset: {:x?}",eatoffset);
        //println!("EOT Offset: {:x?}",eotoffset);
        //println!("ENT Offset: {:x?}",entoffset);

        for i in 0..exporttable.NumberOfNames{
                unsafe{
                    let mut funcrva = std::ptr::read(self.bytecontent[(entoffset + i*4) as usize..].as_ptr() as *const u32);
                    //println!("funcaddr: {:x?}",funcrva);
                    let funcaddr = self.rvatooffset(funcrva).unwrap();
                    
                    let funcname = ReadStringFromMemory(GetCurrentProcess(), self.bytecontent[funcaddr as usize..].as_ptr() as *const c_void);
                    //println!("FUNCTION NAME: {}",funcname);
                    

                    let ordinalvalue = std::ptr::read(self.bytecontent[(eotoffset + i*2) as usize..].as_ptr() as *const u16);
                    //println!("ordinal value: {}",ordinalvalue);

                    let mut funcrva = std::ptr::read(self.bytecontent[(eatoffset + ordinalvalue as u32*4) as usize..].as_ptr() as *const u32);
                    //println!("function rva: {:x?}",funcrva);

                    let mut temp:HashMap<String,u32> = HashMap::new();
                    temp.insert(funcname, funcrva);
                    rvas.push(temp);
                    
                }
        }

        exports.insert(dllname, rvas);
        return exports;

    }


    fn getexportsandforwards(&self) -> HashMap<String,Vec<HashMap<Vec<String>,u32>>>{

        let mut exports:HashMap<String,Vec<HashMap<Vec<String>,u32>>> = HashMap::new();
        let mut rvas: Vec<HashMap<Vec<String>,u32>> = Vec::new();
        let sections = self.getsectionheaders().unwrap();
        
        let exporttable = self.getexportdirectory().unwrap();

        let mut nameoffset = 0;
        let mut eatoffset = 0;
        let mut eotoffset = 0;
        let mut entoffset = 0;

        for i in 0..sections.len(){
            if exporttable.Name > sections[i].VirtualAddress &&
                exporttable.Name < (sections[i].VirtualAddress + sections[i].VirtualSize){
                    nameoffset = exporttable.Name - sections[i].VirtualAddress;
                    nameoffset += sections[i].PointerToRawData;

                    eatoffset = exporttable.AddressOfFunctions -sections[i].VirtualAddress;
                    eatoffset += sections[i].PointerToRawData;

                    eotoffset = exporttable.AddressOfNameOrdinals -sections[i].VirtualAddress;
                    eotoffset += sections[i].PointerToRawData;

                    entoffset = exporttable.AddressOfNames -sections[i].VirtualAddress;
                    entoffset += sections[i].PointerToRawData;

                    break;
                }
            


            
        }

        //println!("Name offset: {:x?}",nameoffset);
        let mut dllname = String::new();
        unsafe{
        dllname = ReadStringFromMemory(GetCurrentProcess(), self.bytecontent[nameoffset as usize..].as_ptr() as *const c_void);
        //println!("dllname: {}",dllname);
        //exports.insert(dllname, Vec::new());
        }
        
        //println!("EAT Offset: {:x?}",eatoffset);
        //println!("EOT Offset: {:x?}",eotoffset);
        //println!("ENT Offset: {:x?}",entoffset);

        for i in 0..exporttable.NumberOfFunctions{
                unsafe{
                    let mut funcrva = std::ptr::read(self.bytecontent[(entoffset + i*4) as usize..].as_ptr() as *const u32);
                    //println!("funcaddr: {:x?}",funcrva);
                    let funcaddr = self.rvatooffset(funcrva).unwrap();
                    
                    let funcname = ReadStringFromMemory(GetCurrentProcess(), self.bytecontent[funcaddr as usize..].as_ptr() as *const c_void);
                    //println!("FUNCTION NAME: {}",funcname);
                    
                    if funcname!=""{
                    let ordinalvalue = std::ptr::read(self.bytecontent[(eotoffset + i*2) as usize..].as_ptr() as *const u16);
                    //println!("ordinal value: {}",ordinalvalue);

                    let mut funcrva = std::ptr::read(self.bytecontent[(eatoffset + ordinalvalue as u32*4) as usize..].as_ptr() as *const u32);
                    //
                    //println!("function rva: {:x?}",funcrva);
                    let fileoffsetfuncrva = self.rvatooffset(funcrva).unwrap();
                    let forwardername = ReadStringFromMemory(GetCurrentProcess(), self.bytecontent[fileoffsetfuncrva as usize..].as_ptr() as *const c_void);
                    //println!("forwarder dll: {}",forwardername);

                    let mut temp:HashMap<Vec<String>,u32> = HashMap::new();
                    temp.insert(vec![funcname,forwardername], funcrva);
                    rvas.push(temp);
                    }
                    
                }
        }

        exports.insert(dllname, rvas);
        return exports;

    }


    fn getexportsordinals(&self) -> Vec<HashMap<String,u32>>{

        
        let mut exportordinals: Vec<HashMap<String,u32>> = Vec::new();
        
        let sections = self.getsectionheaders().unwrap();
        
        let exporttable = self.getexportdirectory().unwrap();

        let mut nameoffset = 0;
        let mut eatoffset = 0;
        let mut eotoffset = 0;
        let mut entoffset = 0;

        for i in 0..sections.len(){
            if exporttable.Name > sections[i].VirtualAddress &&
                exporttable.Name < (sections[i].VirtualAddress + sections[i].VirtualSize){
                    nameoffset = exporttable.Name - sections[i].VirtualAddress;
                    nameoffset += sections[i].PointerToRawData;

                    eatoffset = exporttable.AddressOfFunctions -sections[i].VirtualAddress;
                    eatoffset += sections[i].PointerToRawData;

                    eotoffset = exporttable.AddressOfNameOrdinals -sections[i].VirtualAddress;
                    eotoffset += sections[i].PointerToRawData;

                    entoffset = exporttable.AddressOfNames -sections[i].VirtualAddress;
                    entoffset += sections[i].PointerToRawData;

                    break;
                }
            


            
        }

        //println!("Name offset: {:x?}",nameoffset);
        let mut dllname = String::new();
        unsafe{
        dllname = ReadStringFromMemory(GetCurrentProcess(), self.bytecontent[nameoffset as usize..].as_ptr() as *const c_void);
        //println!("dllname: {}",dllname);
        //exports.insert(dllname, Vec::new());
        }
        
        //println!("EAT Offset: {:x?}",eatoffset);
        //println!("EOT Offset: {:x?}",eotoffset);
        //println!("ENT Offset: {:x?}",entoffset);

        for i in 0..exporttable.NumberOfFunctions{
                unsafe{
                    let mut funcrva = std::ptr::read(self.bytecontent[(entoffset + i*4) as usize..].as_ptr() as *const u32);
                    
                    
                    
                    let funcaddr = self.rvatooffset(funcrva).unwrap();
                    
                    let funcname = ReadStringFromMemory(GetCurrentProcess(), self.bytecontent[funcaddr as usize..].as_ptr() as *const c_void);
                    
                    
                    if funcname!=""{
                       // println!("FUNCTION NAME: {}",funcname);
                    let ordinalvalue = std::ptr::read(self.bytecontent[(eotoffset + i*2) as usize..].as_ptr() as *const u16);
                    //println!("ordinal value: {}",ordinalvalue);

                    let mut funcrva = std::ptr::read(self.bytecontent[(eatoffset + (ordinalvalue as u32*4)) as usize..].as_ptr() as *const u32);
                    //println!("function rva: {:x?}",funcrva);

                    let mut h1:HashMap<String,u32> = HashMap::new(); 
                    h1.insert(funcname, ordinalvalue as u32);
                    exportordinals.push( h1);

                    }

                }
        }

        //exportordinals.push( h1);
        return exportordinals;

    }



    fn getimports(&self) -> Result<Vec<HashMap<String,Vec<String>>>,String>{

        let mut finalimports:Vec<HashMap<String,Vec<String>>> = Vec::new();

        let ntheader = self.getntheader().unwrap();

        if ntheader.OptionalHeader.DataDirectory[1].VirtualAddress==0{
            return Err("Empty Import table".to_string());
        }

        let mut firstimportdirectory = self.rvatooffset(ntheader.OptionalHeader.DataDirectory[1].VirtualAddress).unwrap();
        //println!("{:x?}",firstimportdirectory);

        

        unsafe{

            loop {


                let firstimport = *(self.bytecontent[firstimportdirectory as usize..].as_ptr() as *const IMAGE_IMPORT_DESCRIPTOR);
                
                if firstimport.Name == 0{
                    break;
                }

                let mut firstthunkptr = firstimport.FirstThunk;
                //println!("FirstThunk: {:x?}",firstthunkptr);

                
                let mut hm:HashMap<String,Vec<String>> = HashMap::new();

                let dllname = ReadStringFromMemory(GetCurrentProcess(), self.bytecontent[self.rvatooffset(firstimport.Name).unwrap() as usize..].as_ptr() as *const c_void);
                //println!("{}",dllname);

                let mut v1:Vec<String> =Vec::new();

                let mut originalfirstthunkptr = self.rvatooffset(*firstimport.u.OriginalFirstThunk()).unwrap() as usize;
                //println!("OriginalFirstThunk: {:x?}",firstimport.u.OriginalFirstThunk());
                
                loop{
                    

                    let importthunk = std::ptr::read(self.bytecontent[originalfirstthunkptr..originalfirstthunkptr+8 ].as_ptr() as *const u64);
                    
                    if importthunk == 0{
                        break;
                    }
                    
                    //println!("import thunk: {:x?}",importthunk as u32);
                    let funcptr = match self.rvatooffset(importthunk as u32){
                        Ok(i) =>i,
                        Err(e) => {originalfirstthunkptr += 8;continue;}
                    };
                    //println!("funcptr: {:x?}",funcptr);
                    let funcname = ReadStringFromMemory(GetCurrentProcess(), self.bytecontent[funcptr as usize+2..].as_ptr() as *const c_void);
                    v1.push(funcname);
                    //println!("function name: {}",funcname);
                    originalfirstthunkptr += 8;

                }

                firstimportdirectory += std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>() as u32;
                hm.insert(dllname, v1);
                finalimports.push(hm);
            }

            return Ok(finalimports);
        }
        Err("unable to parse".to_string())
    }



}


use std::env;
use winapi::um::tlhelp32::*;
use winapi::shared::winerror::*;
#[macro_use]
extern crate litcrypt;
//use_litcrypt!("MY-SECRET-SPELL");


struct peloader64{
    path: String,
    bytecontent: Vec<u8>
}


// associated functions
impl peloader64{

    /// this function takes filepath as parameter and 
    /// returns a peloader64 struct object or an error 
    fn from_file(filepath: String) -> Result<peloader64,String>{
        
        let f = match File::open(&filepath){
            Ok(f) => f,
            Err(e) => {return Err(e.to_string())},
        };

        let mut bufferreader = BufReader::new(f);
        let mut pebuffer: Vec<u8> = Vec::new();

        let res1 = match bufferreader.read_to_end(&mut pebuffer){
            Ok(i) => i,
            Err(e) => {return Err(e.to_string())},
        };

        if pebuffer[0]==0x4d  && pebuffer[1] ==0x5a{
            let peloader = peloader64{path:filepath,bytecontent:pebuffer};
            if peloader.ispe64(){
                return Ok(peloader);
            }
        }

        Err("not a valid pe file".to_string())

    }


    /// this function takes an u8 vector byte array and 
    /// returns a peloader64 struct object or an error
    fn from_bytes(contents: Vec<u8>) -> Result<peloader64,String>{

        if contents[0]==0x4d && contents[1]==0x5a{
            let peloader = peloader64{path:"".to_string(),bytecontent:contents};
            if peloader.ispe64(){
                return Ok(peloader);
            }
        }

        Err("not a valid pe file".to_string())

    }


}



impl peloader64{


    fn ispe64(&self) -> bool {
        unsafe{
            let dosheader = *(self.bytecontent[0..64].as_ptr() as *const IMAGE_DOS_HEADER);
            let signature = *(self.bytecontent[dosheader.e_lfanew as usize
            .. ].as_ptr() as *const [u8;4]);
            
            if signature[0]==0x50 && signature[1]==0x45{
                let fileheader  = *(self.bytecontent[(dosheader.e_lfanew +4)as usize
                    .. ].as_ptr() as *const IMAGE_FILE_HEADER);
                if fileheader.Machine==0x8664{
                    return true;
                }
            }
            
        }

        return false;
    }

    fn getsizeofimage(&self) -> usize {

        unsafe{
            let dosheader = *(self.bytecontent[0..64].as_ptr() as *const IMAGE_DOS_HEADER);
            let ntheaders = *(self.bytecontent[dosheader.e_lfanew as usize
            .. ].as_ptr() as *const IMAGE_NT_HEADERS64);
            return ntheaders.OptionalHeader.SizeOfImage as usize;
        }
    }

    fn getsizeofheaders(&self) -> usize{
        unsafe{
            let dosheader = *(self.bytecontent[0..64].as_ptr() as *const IMAGE_DOS_HEADER);
            let ntheaders = *(self.bytecontent[dosheader.e_lfanew as usize
            .. ].as_ptr() as *const IMAGE_NT_HEADERS64);
            return ntheaders.OptionalHeader.SizeOfHeaders as usize;
        }
    }

    fn load(&self, prochandle: *mut c_void) -> Result<String,String> {

        unsafe{

            let baseaddress = VirtualAllocEx(prochandle, std::ptr::null_mut(), self.getsizeofimage(), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if baseaddress.is_null(){
                return Err(format!("VirtualAllocEx failed: {}",GetLastError()));
            }


            // writing headers into process memory
            let mut byteswritten = 0;
            let res = WriteProcessMemory(prochandle, baseaddress, self.bytecontent.as_ptr() as *const c_void, 
                self.getsizeofheaders(), &mut byteswritten);
            if res==0{
                return Err(format!("WriteProcessMemory failed: {}",GetLastError()));
            }


            let mut dosheader = std::mem::zeroed::<IMAGE_DOS_HEADER>();
            FillStructureFromMemory(&mut dosheader, baseaddress, prochandle);
            println!("{:x?}",dosheader);

            let mut ntheader = std::mem::zeroed::<IMAGE_NT_HEADERS64>();
            FillStructureFromMemory(&mut ntheader, (baseaddress as usize+dosheader.e_lfanew as usize) as *const c_void, prochandle);
            println!("{:x?}",ntheader.OptionalHeader.AddressOfEntryPoint);


            let sectionbase = (baseaddress as usize + dosheader.e_lfanew as usize + (std::mem::size_of::<IMAGE_NT_HEADERS64>()));


            let mut sections: Vec<IMAGE_SECTION_HEADER> = Vec::new();

            // allocating sections
            for i in 0..ntheader.FileHeader.NumberOfSections{

                let mut section =std::mem::zeroed::<IMAGE_SECTION_HEADER>();
                FillStructureFromMemory(&mut section,((sectionbase  as usize)+ (i as usize*std::mem::size_of::<IMAGE_SECTION_HEADER>() as usize)) as *const c_void,prochandle);
                println!("{:x?}",section);

                let mut byteswritten = 0;
                let res = WriteProcessMemory(prochandle, 
                    (baseaddress as usize + section.VirtualAddress as usize) as *mut c_void, 
                    self.bytecontent[section.PointerToRawData as usize..].as_ptr() as *const c_void, 
                        section.SizeOfRawData as usize, &mut byteswritten );
                
                sections.push(section);
            }



            // fixing imports
            
            let mut firstimportaddress = baseaddress as usize + ntheader.OptionalHeader.DataDirectory[1].VirtualAddress as usize; 

            let mut firstimport = std::mem::zeroed::<IMAGE_IMPORT_DESCRIPTOR>();
            FillStructureFromMemory(&mut firstimport , firstimportaddress as *const c_void, prochandle);
            
            loop {
                
                if firstimport.Name ==0{
                    break;
                }
                
                let importdllname = ReadStringFromMemory(prochandle, (baseaddress as usize+ firstimport.Name as usize) as *const c_void);
                println!("dllname: {}",importdllname);
                let dllhandle = GetModuleHandleA(importdllname.as_bytes().as_ptr() as *const i8);
            
                let mut originalfirstthunkaddress = baseaddress as usize + *firstimport.u.OriginalFirstThunk() as usize;
                let mut i = 0;
                let mut firstthunkaddress = baseaddress as usize + firstimport.FirstThunk as usize;
                
                loop{
                    let mut importnameptr:Vec<u8> = vec![0;8];
                    let mut byteswritten = 0;
                    ReadProcessMemory(prochandle, originalfirstthunkaddress as *const c_void, 
                       importnameptr.as_mut_ptr() as *mut c_void , 8, &mut byteswritten );
                    
                    let importnameptr = u64::from_ne_bytes(importnameptr[..].try_into().unwrap());

                    if importnameptr == 0{
                        break;
                    }
                    
                    let funcname = ReadStringFromMemory(prochandle, (baseaddress as usize + importnameptr as usize + 2) as *const c_void);

                    println!("funcname: {}",funcname);

                    if funcname!=""{
                        let funcaddress = GetProcAddress(dllhandle, funcname.as_bytes().as_ptr() as *const i8);
                        let x = u64::to_ne_bytes((funcaddress as u64).try_into().unwrap());
                        let mut byteswritten = 0;
                        WriteProcessMemory(prochandle, 
                            (firstthunkaddress+(i*8)) as *mut c_void,
                            x.as_ptr() as *const c_void , 8, &mut byteswritten);

                    }
                    i+=1;

                    originalfirstthunkaddress += 8;
                }

                firstimportaddress += std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
                FillStructureFromMemory(&mut firstimport , firstimportaddress as *const c_void, prochandle);
            
            }





            // fixing base relocations
            if ntheader.OptionalHeader.DataDirectory[5].Size!=0{
                let mut firstbasereloc = baseaddress as usize + ntheader.OptionalHeader.DataDirectory[5].VirtualAddress as usize;

                let mut baserelocation = std::mem::zeroed::<IMAGE_BASE_RELOCATION>();
                FillStructureFromMemory(&mut baserelocation, firstbasereloc as *const c_void, prochandle);


                loop{

                    if baserelocation.VirtualAddress == 0{
                        break;
                    }

                    //println!("{:x?}",baserelocation.VirtualAddress);
                    let entriescount = (baserelocation.SizeOfBlock-8)/2;
                    let mut firstreloc = firstbasereloc + 8;

                    for i in 0..entriescount{
                        let mut buffer:Vec<u8> = vec![0;2];
                        let mut bytesread = 0;
                        ReadProcessMemory(prochandle, 
                            firstreloc as *const c_void, 
                            buffer.as_mut_ptr() as *mut c_void, 
                            2,&mut bytesread );
                      
                        let relocoffset = u16::from_ne_bytes(buffer.try_into().unwrap());
                        if /*relocoffset&0xA000 == 0xA000*/ relocoffset>>12 ==0xA{
                            println!("{:x?}",(baserelocation.VirtualAddress+ (relocoffset&0x0fff)as u32));
                            let mut buffer2:Vec<u8> = vec![0;8];
                            let mut bytesread2 = 0;

                            ReadProcessMemory(prochandle, 
                                (baseaddress as usize + (baserelocation.VirtualAddress+ (relocoffset&0x0fff)as u32) as usize) as *const c_void, 
                                buffer2.as_mut_ptr() as *mut c_void, 8, &mut bytesread2);
                            
                            let value1 = u64::from_ne_bytes(buffer2[..].try_into().unwrap());
                            println!("value1: {:x?}",value1);

                            let delta =   baseaddress as isize - ntheader.OptionalHeader.ImageBase as isize;
                            let finalvalue = value1 as isize+delta;
                            println!("base address: {:x?}",baseaddress);
                            println!("imagebase: {:x?}",ntheader.OptionalHeader.ImageBase);
                            println!("after delta: {:x?}",finalvalue);
                            let buffer3 = isize::to_ne_bytes(finalvalue);
                            let mut byteswritten = 0;
                            WriteProcessMemory(prochandle, 
                                (baseaddress as usize + (baserelocation.VirtualAddress+ (relocoffset&0x0fff)as u32) as usize) as *mut c_void, 
                                 finalvalue.to_ne_bytes().as_ptr() as *const c_void, 8, 
                                &mut byteswritten);

                        }                            
                        //println!("{:x?}",relocoffset);

                        
                        
                        
                        firstreloc += 2;
                    
                    }

                    firstbasereloc += baserelocation.SizeOfBlock as usize;
                    FillStructureFromMemory(&mut baserelocation, firstbasereloc as *const c_void, prochandle);

                }


            }




            let mut threadid = 0;
            let threadhandle = CreateRemoteThread(prochandle, 
                std::ptr::null_mut(), 0, 
                std::mem::transmute(baseaddress as usize +ntheader.OptionalHeader.AddressOfEntryPoint as usize), 
                std::ptr::null_mut(), 0, &mut threadid);

            if threadhandle.is_null(){
                println!("CreateRemoteThread failed: {}",GetLastError());
                VirtualFreeEx(prochandle, baseaddress, 0, MEM_RELEASE);
            }

            WaitForSingleObject(threadhandle, 0xFFFFFFFF);
            





            // freeing the memory
            VirtualFreeEx(prochandle, baseaddress, 0, MEM_RELEASE);

            Ok("Loaded succesfully".to_string())

        }

    }

    fn swapexportordinals(&self,dllbase: *mut c_void,prochandle: *mut c_void, swap1: String, swap2: String) {

        unsafe{
    
            let mut dosheader = std::mem::zeroed::<IMAGE_DOS_HEADER>();
            FillStructureFromMemory(&mut dosheader, dllbase, prochandle);
            
    
            if dosheader.e_magic!=0x5a4d{
                return ();
            }
    
            //println!("{:x?}",dosheader);
    
            let mut ntheader = std::mem::zeroed::<IMAGE_NT_HEADERS64>();
            FillStructureFromMemory(&mut ntheader, (dllbase as usize+dosheader.e_lfanew as usize)as *mut c_void, prochandle);
    
            //println!("{:x?}",ntheader.Signature);
    
            if ntheader.OptionalHeader.DataDirectory[0].Size ==0{
                return ();
            }
    
            let mut sections:Vec<IMAGE_SECTION_HEADER> = vec![std::mem::zeroed::<IMAGE_SECTION_HEADER>();ntheader.FileHeader.NumberOfSections as usize];
    
            for i in 0..ntheader.FileHeader.NumberOfSections{
                let sectionaddr = dllbase as usize + dosheader.e_lfanew as usize+ 
                std::mem::size_of_val(&ntheader) +(i as usize*std::mem::size_of::<IMAGE_SECTION_HEADER>() as usize);
                FillStructureFromMemory(&mut sections[i as usize], sectionaddr as *mut c_void, prochandle);
    
            }
    
            //println!("{:x?}",sections);
    
    
    
            let mut exports:HashMap<String,Vec<HashMap<String,u32>>> = HashMap::new();
            let mut rvas: Vec<HashMap<String,u32>> = Vec::new();
           
    
            let mut exporttable = std::mem::zeroed::<IMAGE_EXPORT_DIRECTORY>();
            FillStructureFromMemory(&mut exporttable,(dllbase as usize + ntheader.OptionalHeader.DataDirectory[0].VirtualAddress as usize) as *mut c_void,prochandle);
    
            let mut nameoffset = exporttable.Name;
            let mut eatoffset = exporttable.AddressOfFunctions;
            let mut eotoffset = exporttable.AddressOfNameOrdinals;
            let mut entoffset = exporttable.AddressOfNames;
    
            
            let mut source1 :[u8;2] = [0;2];
            let mut source2 :[u8;2] = [0;2];
            let mut ord1:usize = 0;
            let mut ord2:usize= 0;
    
            //println!("Name offset: {:x?}",nameoffset);
            let mut dllname = String::new();
            unsafe{
            dllname = ReadStringFromMemory(GetCurrentProcess(), (dllbase as usize + exporttable.Name as usize) as *mut c_void);
            //println!("dllname: {}",dllname);
            //exports.insert(dllname, Vec::new());
            }
            
            //println!("EAT Offset: {:x?}",eatoffset);
            //println!("EOT Offset: {:x?}",eotoffset);
            //println!("ENT Offset: {:x?}",entoffset);
    
            for i in 0..exporttable.NumberOfFunctions{
                    unsafe{
                        let mut funcrva:[u8;4] = [0;4];
                        let mut bytesread = 0;
                        ReadProcessMemory(prochandle, (dllbase as usize+entoffset as usize + i as usize*4) as *const c_void, funcrva.as_mut_ptr() as *mut c_void, 4, &mut bytesread);
                           // self.bytecontent[(entoffset + i*4) as usize..].as_ptr() as *const u32
                        
                        //println!("funcaddr: {:x?}",funcrva);
                        let funcaddr = u32::from_ne_bytes(funcrva);
                        
                        let funcname = ReadStringFromMemory(prochandle, (dllbase as usize + funcaddr as usize) as *mut c_void);
                        //println!("FUNCTION NAME: {}",funcname);
                        
                        if funcname ==swap1 || funcname ==swap2{
                            //println!("{}",funcname);
                        }
    
                        if funcname!=""{
                        let  mut ordinalvalue:[u8;2] = [0;2];
                        let res = ReadProcessMemory(prochandle, (dllbase as usize+eotoffset as usize + i as usize*2) as *const c_void, ordinalvalue.as_mut_ptr() as *mut c_void, 2, &mut bytesread);
                        if res==0{
                            println!("readprocessmemory failed: {}",GetLastError());
                        }
                        
                        let ordinalvalue2 = u16::from_ne_bytes(ordinalvalue);
    
    
                        
    
    
                        if funcname == swap1{
                            ord1 = (dllbase as usize+eotoffset as usize + i as usize*2);
                            println!("swap1: {} ordinalvalue: {}",swap1,ordinalvalue2);
                            println!("ordinal value: {:?}",ordinalvalue);
                            source1[0] = ordinalvalue[0];
                            source1[1] = ordinalvalue[1];
                            println!("source1: {:?}",source1);
                            println!("source2: {:?}",source2);
    
                            if u16::from_ne_bytes(source2)!=0{
                                println!("Writing processmemory  in swap1");
                                let mut oldprotect = 0;
    
                                VirtualProtectEx(prochandle, ord1 as *mut c_void, 
                                 2, PAGE_READWRITE, &mut oldprotect);
                                let res = WriteProcessMemory(prochandle, ord1 as *mut c_void, source2.as_mut_ptr() as *mut c_void, 2, &mut bytesread);
                                if res==0{
                                    println!("writeprocessmemory failed: {}",GetLastError());
                                }
    
                                if ord2!=0 && u16::from_ne_bytes(source1)!=0 {
                                    VirtualProtectEx(prochandle, ord2 as *mut c_void, 
                                        2, PAGE_READWRITE, &mut oldprotect);
                                       let res = WriteProcessMemory(prochandle, ord2 as *mut c_void, source1.as_mut_ptr() as *mut c_void, 2, &mut bytesread);
                                       if res==0{
                                           println!("writeprocessmemory failed: {}",GetLastError());
                                       }
                                }
    
    
    
                            }
    
                        }
    
    
    
                        if funcname == swap2{
                            println!("swap2: {} ordinalvalue: {}",swap2,ordinalvalue2);
                            ord2 = (dllbase as usize+eotoffset as usize + i as usize*2);
                            println!("ordinal value: {:?}",ordinalvalue);
                            source2 = ordinalvalue2.to_ne_bytes();
                            println!("source1: {:?}",source1);
                            println!("source2: {:?}",source2);
    
                            if u16::from_ne_bytes(source1)!=0{
                                println!("Writing processmemory  in swap2");
                                println!("{:?}",source1);
                                let mut oldprotect = 0;
    
                                
                                VirtualProtectEx(prochandle, ord2 as *mut c_void, 
                                 2, PAGE_READWRITE, &mut oldprotect);
                                let res = WriteProcessMemory(prochandle, ord2 as *mut c_void, source1.as_mut_ptr() as *mut c_void, 2, &mut bytesread);
                                if res==0{
                                    println!("writeprocessmemory2 failed: {}",GetLastError());
                                }
    
                                if ord1!=0 && u16::from_ne_bytes(source2)!=0 {
                                    VirtualProtectEx(prochandle, ord1 as *mut c_void, 
                                        2, PAGE_READWRITE, &mut oldprotect);
                                       let res = WriteProcessMemory(prochandle, ord1 as *mut c_void, source2.as_mut_ptr() as *mut c_void, 2, &mut bytesread);
                                       if res==0{
                                           println!("writeprocessmemory failed: {}",GetLastError());
                                       }
                                }
    
    
                            }
    
                        }
    
    
                        //let mut funcrva = std::ptr::read(self.bytecontent[(eatoffset + ordinalvalue as u32*4) as usize..].as_ptr() as *const u32);
                        //println!("function rva: {:x?}",funcrva);
    
                        let mut rvafunction :[u8;4] = [0;4];
                        ReadProcessMemory(prochandle, (dllbase as usize + eatoffset as usize + (ordinalvalue2 as usize * 4)) as *const c_void, 
                        rvafunction.as_mut_ptr() as *mut c_void, 4, &mut bytesread);
    
                        
                        let mut temp:HashMap<String,u32> = HashMap::new();
                        temp.insert(funcname, u32::from_ne_bytes(rvafunction));
                        rvas.push(temp);
                    }
                    }
            }
    
            exports.insert(dllname, rvas);
            //return Ok(exports);
    
    
    
        }
    
    }
    
    


}


use winapi::um::winbase::*;
use winapi::um::winuser::*;


fn main() {
    
    let arguments = env::args().collect::<Vec<String>>();

    if arguments.len()!=2{
        println!("Sorry try again");
        std::process::exit(0);
    }

    let mut pe = peparse64::parsefile(arguments[1].to_string());
    if pe.ispefile()==false{
        println!("Upload 64bit exe's only");
        std::process::exit(0);
    }



    //"D:\rust_practice\createdll\target\release\createdll.dll"
    //let mut pe = peparse64::parsefile("D:\\rust_practice\\helloworld\\target\\release\\helloworld.exe".to_string());
    
    
    /* CHALLENGE 1
    let mut pe = peparse64::parsefile(arguments[1].to_string());
    if pe.ispefile() == false{
        println!("Invalid pe file, currently accepting only 64bit dll's");
        std::process::exit(0);
    }
    //println!("{:x?}",pe.bytecontent[0]);
    /*let dosheader = pe.getdosheader().unwrap();
    println!("{:x?}",dosheader.e_magic);
    println!("{:x?}",dosheader.e_lfanew);
    
    let ntheader = pe.getntheader().unwrap();
    println!("{:x?}",ntheader.FileHeader.Machine);
    println!("number of sections: {:x?}",ntheader.FileHeader.NumberOfSections);
    println!("size of optionalheader: {:x?}",ntheader.FileHeader.SizeOfOptionalHeader);
    println!("File characteristics: {:x?}",ntheader.FileHeader.Characteristics);


    println!("Address of Entry Point: {:x?}",ntheader.OptionalHeader.AddressOfEntryPoint);
    println!("ImageBase: {:x?}",ntheader.OptionalHeader.ImageBase);
    println!("File Alignment: {:x?}",ntheader.OptionalHeader.FileAlignment);
    println!("Section Alignment: {:x?}",ntheader.OptionalHeader.SectionAlignment);
    println!("Total Size of Image: {:x?}",ntheader.OptionalHeader.SizeOfImage);
    println!("size of headers: {:x?}",ntheader.OptionalHeader.SizeOfHeaders);

    println!("Export table rva: {:x?}",ntheader.OptionalHeader.DataDirectory[0].VirtualAddress);

    let sections = pe.getsectionheaders().unwrap();

    /*for i in 0..sections.len(){
        println!("Section name: {}",String::from_utf8_lossy(&sections[i].Name));
        println!("Virtual Address: {:x?}",sections[i].VirtualAddress);
        println!("Virtual Size: {:x?}",sections[i].VirtualSize);
        println!("PointerToRawData: {:x?}",sections[i].PointerToRawData);
        println!("SizeofRawData: {:x?}",sections[i].SizeOfRawData);
    }*/

    println!("Exports");
    println!("Exports rva: {:x?}",ntheader.OptionalHeader.DataDirectory[0].VirtualAddress);
    println!("Exports size: {:x?}",ntheader.OptionalHeader.DataDirectory[0].Size);


    let exporttable = pe.getexportdirectory().unwrap();
    println!("{:x?}",exporttable);*/


    let exports = pe.getexports();
    //let funcnames = exports.get("createdll.dll").unwrap();
    
    for i in exports.keys(){
        for j in &exports[i]{
            for k in j.keys(){
                if k==&arguments[2]{
                    println!("True");
                    let fl = String::from("EXE{puerto dll exporto}");
                    println!("{}",fl);
                    std::process::exit(0);
                }
            }
        }
    }

    println!("Function not found in the dll");*/

    


 

}



#[derive(Clone,Copy,Debug)]
#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub Version: IMAGE_VERSION<u16>,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFunctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,
    pub AddressOfNames: u32,
    pub AddressOfNameOrdinals: u32,
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


#[derive(Clone,Copy,Debug)]
#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: LONG,
}



#[derive(Clone,Copy,Debug)]
#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}


#[derive(Clone,Copy,Debug)]
#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {

    pub Magic: u16,
    pub LinkerVersion: IMAGE_VERSION<u8>,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub OperatingSystemVersion: IMAGE_VERSION<u16>,
    pub ImageVersion: IMAGE_VERSION<u16>,
    pub SubsystemVersion: IMAGE_VERSION<u16>,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 0],
}


#[derive(Clone,Copy,Debug)]
#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}


#[derive(Clone,Copy,Debug)]
#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub VirtualSize: u32,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}


#[derive(Clone,Copy,Debug)]
#[repr(C)]
pub struct IMAGE_VERSION<T> {
    pub Major: T,
    pub Minor: T,
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



