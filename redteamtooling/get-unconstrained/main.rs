use ldap3::asn1::Null;
use ldap3::result::Result;
use ldap3::{LdapConn, LdapConnAsync, Scope, SearchEntry};
use std::char::decode_utf16;
use std::collections::HashMap;
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
        "(&(objectclass=user))",
        vec!["cn", "objectsid", "useraccountcontrol"],
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
        let mut istrustedfordeleg = false;

        if se.attrs.get("userAccountControl").is_some() {
            let uac = se.attrs.get("userAccountControl").unwrap();
            for i in 0..uac.len() {
                let temp = uac[i].parse::<u32>().unwrap();
                let uacvalues = decodeuac(temp);

                for j in uacvalues {
                    if j == "TRUSTED_FOR_DELEGATION" {
                        istrustedfordeleg = true;
                    }
                }
            }
        }

        if istrustedfordeleg == false {
            continue;
        }

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

pub fn decodeuac(uac: u32) -> Vec<String> {
    use indexmap;

    let mut uactable = indexmap::indexmap! {
        "PARTIAL_SECRETS_ACCOUNT" => 0x04000000,
        "TRUSTED_TO_AUTH_FOR_DELEGATION"=> 0x1000000,
        "PASSWORD_EXPIRED"=> 0x800000,
        "DONT_REQ_PREAUTH"=> 0x400000,
        "USE_DES_KEY_ONLY"=> 0x200000,
        "NOT_DELEGATED"=> 0x100000,
        "TRUSTED_FOR_DELEGATION"=> 0x80000,
        "SMARTCARD_REQUIRED"=> 0x40000,
        "MNS_LOGON_ACCOUNT"=> 0x20000,
        "DONT_EXPIRE_PASSWORD"=> 0x10000,
        "SERVER_TRUST_ACCOUNT"=> 0x2000,
        "WORKSTATION_TRUST_ACCOUNT"=> 0x1000,
        "INTERDOMAIN_TRUST_ACCOUNT"=> 0x0800,
        "NORMAL_ACCOUNT"=> 0x0200,
        "TEMP_DUPLICATE_ACCOUNT"=> 0x0100,
        "ENCRYPTED_TEXT_PWD_ALLOWED"=> 0x0080,
        "PASSWD_CANT_CHANGE"=> 0x0040,
        "PASSWD_NOTREQD"=> 0x0020,
        "LOCKOUT"=> 0x0010,
        "HOMEDIR_REQUIRED"=> 0x0008,
        "ACCOUNTDISABLE"=> 2,
        "SCRIPT"=> 1


    };

    let mut temp = uac;
    let mut uacvalues: Vec<String> = Vec::new();

    for i in uactable {
        let temp2 = i.1;
        if temp | temp2 == temp {
            uacvalues.push(i.0.to_string());
            temp = temp - i.1;
        }
    }

    return uacvalues;
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
