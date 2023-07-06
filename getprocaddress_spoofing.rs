use winapi::um::errhandlingapi::GetLastError;
use winapi::um::winnt::*;
use winapi::ctypes::*;
use winapi::um::libloaderapi::*;
use winapi::um::synchapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::memoryapi::*;
use winapi::um::winuser::*;
use std::collections::*;
use md5::*;

pub fn swapexportordinals(dllbase: *mut c_void,prochandle: *mut c_void, swap1: String, swap2: String) {

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



fn main() {
    
    

        unsafe{
            let modulehandle = LoadLibraryA("User32\0".as_bytes().as_ptr() as *const i8);

            swapexportordinals(modulehandle as *mut c_void, GetCurrentProcess(), "MessageBoxA".to_string(), "ChangeMenuW".to_string());

            let mbox = GetProcAddress(modulehandle, "ChangeMenuW\0".as_bytes().as_ptr() as *const i8);


           // MessageBoxA(hWnd, lpText, lpCaption, uType)


            let mbox2 = std::mem::transmute::<
            *mut c_void,fn(*mut c_void, *const i8, *const i8, u32) -> i32>(mbox as *mut c_void);
       
            mbox2(std::ptr::null_mut(),
            "Hi\0".as_bytes().as_ptr() as *const i8,
            "Hi\0".as_bytes().as_ptr() as *const i8,0);
       
        }
    }