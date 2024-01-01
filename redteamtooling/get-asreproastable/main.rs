use ldap3::asn1::Null;
use ldap3::result::Result;
use ldap3::{LdapConn, LdapConnAsync, Scope, SearchEntry};
use std::env;
use winapi::ctypes::*;
use winapi::shared::sddl::*;
use winapi::shared::*;
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::*;

#[derive(Debug)]
struct domaininfo {
    domainname: String,
    dc: String,
    dn: String,
}

impl domaininfo {
    fn new(name: &String, dcname: &String) -> domaininfo {
        // us.techcorp.local -> [us,techcorp,local]
        let distinguishedname = name.split(".").collect::<Vec<&str>>();
        let mut dn1: Vec<String> = Vec::new();
        for i in 0..distinguishedname.len() {
            dn1.push("DC=".to_owned() + distinguishedname[i]);
        }
        let finaldn = dn1.join(",");
        domaininfo {
            domainname: name.clone(),
            dc: dcname.clone(),
            dn: finaldn,
        }
    }
}

fn main() {
    // ourbinary.exe domainname domaincontroller
    let arguments = std::env::args().collect::<Vec<String>>();

    if arguments.len() != 3 {
        println!("Usage: ./binary.exe domainname domaincontroller");
        std::process::exit(0);
    }

    let domain1 = domaininfo::new(&arguments[1], &arguments[2]);

    let ldapconresult = LdapConn::new(&("ldap://".to_string() + &domain1.dc + ":3268"));
    let mut ldapconnection = match ldapconresult {
        Ok(l) => l,
        Err(e) => {
            println!("{}", e);
            std::process::exit(0);
        }
    };

    let bindresult = ldapconnection.sasl_gssapi_bind(&domain1.dc);
    match bindresult {
        Ok(res) => {
            //println!("gssapi bind success")
        }
        Err(e) => {
            println!("Error while binding: {}", e);
            ldapconnection.unbind();
            std::process::exit(0);
        }
    };

    let searchresult = ldapconnection.search(
        &domain1.dn,
        Scope::Subtree,
        "(&(objectclass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
        vec!["cn", "objectsid", "dn"],
    );

    if searchresult.is_err() {
        ldapconnection.unbind();
        std::process::exit(0);
    }

    let results = searchresult.unwrap().success();
    let searchentries = match results {
        Ok(l) => l.0,
        Err(e) => {
            println!("{}", e);
            return ();
        }
    };

    for entry in searchentries {
        let se = SearchEntry::construct(entry);
        println!("{}", se.dn);
        for i in se.attrs {
            println!("{}: {:?}", i.0, i.1.join(","));
        }
        if se.bin_attrs.len() > 0 {
            for i in se.bin_attrs {
                if i.0 == "objectSid" {
                    let sid = ConvertbytestoStringSID(i.1[0].clone());
                    println!("ObjectSID: {}", sid);
                    continue;
                }
                println!("{}: {:?}", i.0, i.1);
            }
        }

        println!("");
    }

    ldapconnection.unbind();
}

pub fn ConvertbytestoStringSID(mut sidbytes: Vec<u8>) -> String {
    unsafe {
        let mut temppointer = 0 as *mut i8;

        let res = ConvertSidToStringSidA(sidbytes.as_mut_ptr() as *mut c_void, &mut temppointer);
        //println!("temppointer: {}",temppointer as u64);

        let sid = ReadStringFromMemory(GetCurrentProcess(), temppointer as *mut c_void);

        return sid;
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
