use indexmap;

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
