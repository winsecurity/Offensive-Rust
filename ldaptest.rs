
use ldap3::*;

use std::{process::exit, vec};
use ldap3::result::Result;

fn main()  {
    
    let ldap =LdapConn::new("ldap://192.168.0.110:3268");

   let mut ldapcon =match ldap{
    Ok(l) => l,
    Err(r) => panic!("{}",r)
   };


    ldapcon.simple_bind("CN=Administrator,CN=Users,DC=tech69,DC=local", "Passw0rd").unwrap();

   let username = "*)(serviceprincipalname=*";
   //let username = "Administrator";
   let filter = "(&(objectclass=user)(samaccountname=".to_owned() + username + "))";

   println!("filter: {}",filter);
   let res =ldapcon.search("DC=tech69,DC=local",Scope::Subtree,&filter[..],vec!["dn"]).unwrap();

   let (re,ldapresult) = res.success().unwrap();

   for i in re{
    println!("{:#?}",SearchEntry::construct(i).dn);
   }

}
