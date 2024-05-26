use std::collections::HashSet;

fn main() {
    fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
        a.iter()
            .zip(b.iter())
            .map(|(a_byte, b_byte)| a_byte ^ b_byte)
            .collect()
    }

    // fn encrypt_bytes(secret: &[u8], msg: &[u8]) -> Vec<u8> {
    //     xor_bytes(secret, msg)
    // }

    // fn decrypt_bytes(secret: &[u8], encrypted_msg: &[u8]) -> Vec<u8> {
    //     encrypt_bytes(secret, encrypted_msg)
    // }

    fn _bytes_to_hex_str(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    fn hex_str_to_bytes(msg: String) -> Vec<u8> {
        hex::decode(msg).expect("Something went wrong")
    }

    let ciphertexts = vec![
        "160111433b00035f536110435a380402561240555c526e1c0e431300091e4f04451d1d490d1c49010d000a0a4510111100000d434202081f0755034f13031600030d0204040e",
        "050602061d07035f4e3553501400004c1e4f1f01451359540c5804110c1c47560a1415491b06454f0e45040816431b144f0f4900450d1501094c1b16550f0b4e151e03031b450b4e020c1a124f020a0a4d09071f16003a0e5011114501494e16551049021011114c291236520108541801174b03411e1d124554284e141a0a1804045241190d543c00075453020a044e134f540a174f1d080444084e01491a090b0a1b4103570740",
        "000000000000001a49320017071704185941034504524b1b1d40500a0352441f021b0708034e4d0008451c40450101064f071d1000100201015003061b0b444c00020b1a16470a4e051a4e114f1f410e08040554154f064f410c1c00180c0010000b0f5216060605165515520e09560e00064514411304094c1d0c411507001a1b45064f570b11480d001d4c134f060047541b185c",
        "0b4916060808001a542e0002101309050345500b00050d04005e030c071b4c1f111b161a4f01500a08490b0b451604520d0b1d1445060f531c48124f1305014c051f4c001100262d38490f0b4450061800004e001b451b1d594e45411d014e004801491b0b0602050d41041e0a4d53000d0c411c41111c184e130a0015014f03000c1148571d1c011c55034f12030d4e0b45150c5c",
        "011b0d131b060d4f5233451e161b001f59411c090a0548104f431f0b48115505111d17000e02000a1e430d0d0b04115e4f190017480c14074855040a071f4448001a050110001b014c1a07024e5014094d0a1c541052110e54074541100601014e101a5c",
        "0c06004316061b48002a4509065e45221654501c0a075f540c42190b165c",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    ];
    let ciphertexts_in_bytes: Vec<Vec<u8>> = ciphertexts
        .iter()
        .map(|hex| hex_str_to_bytes(hex.to_string()))
        .collect();

    // Just a test to understand what we will get.

    let a: Vec<u8> = xor_bytes(
        "   1234                       ".as_bytes(),
        "ABCDqbcd1234".as_bytes(),
    );
    let chars: String = a.iter().map(|&b| b as char).collect();

    println!("---------------");
    println!("{}", chars);
    println!("---------------");

    // get min len of encrypted messages
    let min_length = ciphertexts_in_bytes.iter().map(|x| x.len()).min().unwrap();

    // Ei xor Ej == Mi xor Mj , from here we can infer the Mi or Mj byte
    // Mi xor S = Ei ====> S = Ei xor Mi , once we get the Mi byte, having the Ei byte we can determine the S (secret key) byte
    for i in 0..ciphertexts_in_bytes.len() {
        let mut xor_ciphertext_ascii = Vec::new();
        for j in 0..i {
            let bytes_xor = xor_bytes(&ciphertexts_in_bytes[i], &ciphertexts_in_bytes[j]);
            let ascii_xor: Vec<char> = bytes_xor
                .iter()
                .map(|&b| {
                    if b.is_ascii_alphanumeric() {
                        b as char
                    } else {
                        '_'
                    }
                })
                .collect();

                xor_ciphertext_ascii.push(ascii_xor.clone());
        }
        let mut secret_hint = String::new();

        for j in 0..min_length {
            let mut possible_letters = HashSet::<char>::new();
            xor_ciphertext_ascii
                .iter()
                .filter(|chars| chars.len() > j)
                .map(|chars| chars[j])
                .filter(|letter| letter != &'_')
                .for_each(|letter| {
                    possible_letters.insert(letter.to_ascii_lowercase());
                });

            if possible_letters.len() == 1 {
                secret_hint.push(*possible_letters.iter().next().unwrap());
            } else if possible_letters.len() > 1 {
                secret_hint.push('#');

                // if we are not sure the frecuency of this letter and want to see alternatives (probable they are wrong, there is no garantee)
                // secret.push('{');
                // for p_letter in possible_letters {
                //     secret.push(p_letter);
                // }
                // secret.push('}');
            } else if possible_letters.len() == 0 {
                secret_hint.push('#');
            }
        }
        println!();
        println!("{}", secret_hint);
    }
}
