use serde_json::Value;
use std::fs;
use sha2::{Digest, Sha256};
use byteorder::{ByteOrder, LittleEndian};
extern crate hex;
use secp256k1::{Secp256k1, PublicKey, Message};
use hex::decode;
use secp256k1::ecdsa::Signature;
use ripemd::Ripemd160;



pub fn p2wpkh_verifier(folder_path: &str)  -> (Vec<String> , Vec<String>){
    let mut number_of_transactions_processed = 0;
    let mut number_of_valid_txn=0;
    let mut number_of_invalid_txn = 0;
    let mut number_of_multi_script_types=0;
    let mut txid_vec: Vec<String> = Vec::new();
    let mut wtxid_vec: Vec<String> = Vec::new();
    if let Ok(entries) = fs::read_dir(folder_path) {
        for entry in entries {
            if let Ok(entry) = entry {
                let file_path = entry.path();
                if let Ok(file_content) = fs::read_to_string(&file_path) {
                    let file_size_kb = (file_content.len() as f64 / 1024.0) as u32;
                    //Using a filer so that we do not read trasaction files of size bigger than 90kb 
                    if(file_size_kb <= 90)   {
                    if let Ok(data) = serde_json::from_str::<Value>(&file_content) {
                        
                        if let Some(vin) = data["vin"].as_array() {
                            let mut flag = true;
                            //Checking if the same transaction contains different script types other than p2pkh
                            for vin_entry in vin {
                                if let (Some(scriptsig_asm), Some(prevout), Some(scriptpubkey_asm)) = (vin_entry["scriptsig_asm"].as_str(), vin_entry["prevout"].as_object(), vin_entry["prevout"]["scriptpubkey_asm"].as_str()) {
                                    if prevout["scriptpubkey_type"].as_str() != Some("v0_p2wpkh") {
                                        flag = false;
                                        break;
                                    }
                                }
                            }
                            if flag {
                                number_of_transactions_processed+=1;
                                let p2wpkh_object = P2WPKH::new(&data);
                                let result = p2wpkh_object.validator();
                                if result {
                                    number_of_valid_txn+=1;
                                    //println!("Validtxn");
                                    txid_vec.push(p2wpkh_object.p2wpkh_transaction_maker(false));
                                    wtxid_vec.push(p2wpkh_object.p2wpkh_transaction_maker(true));
                                }else{
                                    number_of_invalid_txn+=1;
                                   // println!("Invalid txn")
                                }
                            } else{
                                number_of_multi_script_types += 1;
                            }
                        }
                    }
                }
                }
            }
        }
    }
    // println!("{:?}",txid_vec);
    // println!("{:?}",wtxid_vec);
    // println!("Number of transactions processed: {}", number_of_transactions_processed);
    // println!("Number of valid transactions: {}", number_of_valid_txn);
    // println!("Number of invalid transactions: {}", number_of_invalid_txn);
    // println!("Number of transactions with multiple script types: {}", number_of_multi_script_types);

    (txid_vec, wtxid_vec) 

}




fn double_sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(&Sha256::digest(data)).to_vec()
}

//pub_key for p2wpkh is second part of the witness
fn publickey_to_script_code(pubkey: &str) -> String {

    // Decode the public key from hex
    let public_key_bytes = decode(pubkey).expect("Failed to decode public key hex");

    // Calculate SHA-256 hash
    let sha256_bytes = Sha256::digest(&public_key_bytes);
    // println!("SHA-256 Hash: {:?}", sha256_bytes);

    // Calculate RIPEMD-160 hash
    let mut ripemd160_hasher = Ripemd160::new();
    ripemd160_hasher.update(&sha256_bytes);
    let pkh = ripemd160_hasher.finalize();
    let pkh_bytes: Vec<u8> = pkh.as_slice().to_vec();

   pkh_to_script_code(&hex::encode(pkh_bytes))
}
fn pkh_to_script_code(pkh: &str) -> String {
    format!("1976a914{}88ac", pkh)
}
fn verify_ecdsa_signature(signature_hex: &str, public_key_hex: &str, message_hex: &str) -> bool {
      // Decode hex strings into byte arrays
      let signature_bytes = decode(signature_hex).expect("Failed to decode signature hex");
      let public_key_bytes = decode(public_key_hex).expect("Failed to decode public key hex");
      let message_bytes = decode(message_hex).expect("Failed to decode message hex");
  
      // Initialize secp256k1 context
  
      let messag_hash = double_sha256(&message_bytes);
  
      let secp = Secp256k1::new();
  
      // Parse the public key
      let public_key = PublicKey::from_slice(&public_key_bytes).expect("Failed to parse public key");
  
      // Parse the signature
      let signature = Signature::from_der(&signature_bytes).expect("Failed to parse signature");
  
      // Verify the signature
      let message = Message::from_slice(&messag_hash).expect("Failed to parse message");
      let result = secp.verify_ecdsa(&message, &signature, &public_key);
  
      // Check if the signature is valid
      if result.is_ok() {
          true
      } else {
          false
      }
}
fn double_sha256_strings(strings: &[&str]) -> String {
    // Concatenate the strings into a single string
    let concatenated = strings.join("");

    // Convert the hexadecimal string to bytes
    let input_bytes = hex::decode(concatenated).unwrap();

    // Compute the first SHA-256 hash
    let hash1 = Sha256::digest(&input_bytes);

    // Compute the second SHA-256 hash
    let hash2 = Sha256::digest(&hash1);

    // Convert the result to hexadecimal format
    let result_hex = hex::encode(hash2);

    result_hex
}
fn p2wpkh_script_verifier(scriptpubkey_asm: &str, public_key: &str) -> bool {
    // println!("{}", public_key);
 
     // Decode the public key from hex
     let public_key_bytes = decode(public_key).expect("Failed to decode public key hex");
 
     // Calculate SHA-256 hash
     let sha256_bytes = Sha256::digest(&public_key_bytes);
     // println!("SHA-256 Hash: {:?}", sha256_bytes);
 
     // Calculate RIPEMD-160 hash
     let mut ripemd160_hasher = Ripemd160::new();
     ripemd160_hasher.update(&sha256_bytes);
     let pkh = ripemd160_hasher.finalize();
     let pkh_bytes: Vec<u8> = pkh.as_slice().to_vec();
     // println!("RIPEMD-160 Hash (pkh): {}", hex::encode(&pkh_bytes));
 
     // Compare the RIPEMD-160 hash with arr[3]
     let arr: Vec<&str> = scriptpubkey_asm.split(" ").collect();
     hex::encode(&pkh_bytes) == arr[2]
 }

pub struct P2WPKH {
    vin: Vec<Value>,
    vout: Vec<Value>,
    version: u32,
    locktime: u32,
}

impl P2WPKH {
    pub fn new(json_object: &Value) -> Self {
        Self {
            vin: json_object["vin"].as_array().unwrap().to_vec(),
            vout: json_object["vout"].as_array().unwrap().to_vec(),
            version: json_object["version"].as_u64().unwrap() as u32,
            locktime: json_object["locktime"].as_u64().unwrap() as u32,
        }
    }
    pub fn validator(&self) -> bool {
        let mut vin_number = 0;
        let hash_prevouts = self.hash_prevout_calculator() ;
        let hash_sequence= self.hash_sequence_calculator() ;
        let hash_outputs= self.hash_output_calculator();
        for vin in &self.vin {
            
            let valid = self.validate_vin(vin_number,&hash_prevouts,&hash_sequence,&hash_outputs);
            
            if !valid {
                return false;
            }
            vin_number += 1;
        }
        true
    }
   
    pub fn validate_vin(&self, vin_number: usize, hash_prevouts:&str,hash_sequence:&str ,hash_outputs:&str) -> bool {
         

        //Version number
        let version_bytes = self.version.to_le_bytes().iter().map(|&b| format!("{:02x}", b)).collect::<String>();
        /// Locktime and sighash
        let sighashall = "01000000";
        let locktime_hex = self.locktime.to_le_bytes().iter().map(|&b| format!("{:02x}", b)).collect::<String>();
        //println!("{}",locktime_hex);
        

        // vin_number related parameters
        let vin = &self.vin.get(vin_number).unwrap();
        //value of output
        let vin_value = vin["prevout"]["value"].as_u64().unwrap();
        let mut value_bytes = [0; 8]; // 8 bytes for a u64 value
        LittleEndian::write_u64(&mut value_bytes, vin_value);
        let value_bytes_hex = format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",value_bytes[0], value_bytes[1], value_bytes[2], value_bytes[3],value_bytes[4], value_bytes[5], value_bytes[6], value_bytes[7]);
        //sequence of input
        let sequence_num = vin["sequence"].as_u64().unwrap();
        let sequence_num = vin["sequence"].as_u64().unwrap() as u32;
        let mut sequence_num_bytes = [0; 4]; // 4 bytes for a u32 value
        LittleEndian::write_u32(&mut sequence_num_bytes, sequence_num);
        let sequence_num_bytes_hex = format!("{:02x}{:02x}{:02x}{:02x}", sequence_num_bytes[0], sequence_num_bytes[1], sequence_num_bytes[2], sequence_num_bytes[3]);
        //output point 
        let mut output_point = hex::encode(&hex::decode(vin["txid"].as_str().unwrap()).unwrap().into_iter().rev().collect::<Vec<_>>());
        let vout_value = vin["vout"].as_u64().unwrap() as u32;
        let mut vout_bytes = [0; 4];
        LittleEndian::write_u32(&mut vout_bytes, vout_value);
        let vout_bytes_hex = format!("{:02x}{:02x}{:02x}{:02x}", vout_bytes[0], vout_bytes[1], vout_bytes[2], vout_bytes[3]);
        let output_point = format!("{}{}",output_point,vout_bytes_hex);
        //println!("the output point is {}",output_point);
        //Script code
        let mut witness_arr: Vec<String> = Vec::new();
             if let Some(witness) = vin["witness"].as_array() {
                    witness_arr = witness
                    .iter()
                    .map(|w| w.as_str().unwrap_or_default().to_string())
                    .collect();
            }
        let pubkey = witness_arr.get(1).unwrap();
        let script_code = publickey_to_script_code(pubkey);
        //println!("{}", script_code);
        //println!("02000000644a20d5bce337fe14c95b5ef6b3efb28ca22d6efef1db551790a5484f8734de18606b350cd8bf565266bc352f0caddcf01e8fa789dd8a15386327cf8cabe1984d14f6d46a3aa0ced27e22aa89426ec6405ca0f4375ccde4ce50b6ef5dd05a29000000001976a91464d3a83d69d3980774358ba9d0009c1c28b4799688acd054080000000000feffffff99c5f5f5520fb568fd1444a407e6f3646f345c4840e3683d6d254c43b12143ec4dbc0c0001000000");
       
        //Constructing message
        let message = format!(
            "{}{}{}{}{}{}{}{}{}{}",
             version_bytes, hash_prevouts, hash_sequence, output_point, script_code, value_bytes_hex, sequence_num_bytes_hex , hash_outputs, locktime_hex, sighashall
        );
        //println!("{}\n", message);


        let mut signature =  witness_arr.get(0).unwrap().as_str();
         ////////////////////////////////////////////////////////////////
        /// I am not considering transaction other than sighashall so the function returns false
        


        if &signature[signature.len() - 2..] != "01" {
            //println!("not sighashall type signature");
            return false;
        }
        let  scriptpubkey_asm = (vin["prevout"]["scriptpubkey_asm"].as_str().unwrap());
        //Checking that public key is equal to public key hash
        if !p2wpkh_script_verifier(scriptpubkey_asm, pubkey.clone().as_str()){
            return false;
        }
        
        //Checking vin&vout
        let mut vin_value = 0;
        let mut vout_value = 0;
        let mut flag = true;
        for vin in &self.vin {
                vin_value += vin["prevout"]["value"].as_u64().unwrap();
                //checking for zero value transaction and removing them 
                if vin["prevout"]["value"].as_u64().unwrap() == 0{
                    flag = false;
                }
        }   
        for vout in &self.vout {
            vout_value += vout["value"].as_u64().unwrap();
        }
        if vin_value <= vout_value && flag{
            return false;
        }
        signature = &signature[..signature.len() - 2];
        //println!("Signature: {}", signature);
       
        //Checking that public key is equal to public key hash
        // yet to be added 
        ///////////////////////////////////////////////////////
        let public_key = pubkey;
        //println!("public key: {}", public_key);
        let check = verify_ecdsa_signature(&signature, &public_key , &message );
        //println!("{}",check);

        true
    }
    pub fn hash_prevout_calculator(&self) -> String {
        //Calculating HashPrevout
        let mut hash_prevouts: Vec<String> = Vec::new(); 
        //making hashPrevout
        for vin in &self.vin {
            //txid
            let txid = hex::encode(&hex::decode(vin["txid"].as_str().unwrap()).unwrap().into_iter().rev().collect::<Vec<_>>());
            //println!("{}", txid);
            //vout
            let vout_value = vin["vout"].as_u64().unwrap() as u32;
            let mut vout_bytes = [0; 4];
            LittleEndian::write_u32(&mut vout_bytes, vout_value);
            let vout_bytes_hex = format!("{:02x}{:02x}{:02x}{:02x}", vout_bytes[0], vout_bytes[1], vout_bytes[2], vout_bytes[3]);
            //println!("{}", vout_bytes_hex);
            
            let hash_prevout_part = format!("{}{}",txid,vout_bytes_hex);
            hash_prevouts.push(hash_prevout_part);
        }
        let hp_vec: Vec<&str> = hash_prevouts.iter().map(|s| s.as_str()).collect();
        let hp = double_sha256_strings(&hp_vec);
        //println!("hash prevout:{}", hp);
        hp
    }
    pub fn hash_sequence_calculator(&self) -> String {
        let mut hash_sequence: Vec<String> = Vec::new(); 
        //making hashPrevout
        for vin in &self.vin {
            let sequence_num = vin["sequence"].as_u64().unwrap();
            let sequence_num = vin["sequence"].as_u64().unwrap() as u32;
            let mut sequence_num_bytes = [0; 4]; // 4 bytes for a u32 value
            LittleEndian::write_u32(&mut sequence_num_bytes, sequence_num);
            let sequence_num_bytes_hex = format!("{:02x}{:02x}{:02x}{:02x}", sequence_num_bytes[0], sequence_num_bytes[1], sequence_num_bytes[2], sequence_num_bytes[3]);
            hash_sequence.push(sequence_num_bytes_hex);
        }
        let hs_vec: Vec<&str> = hash_sequence.iter().map(|s| s.as_str()).collect();
        let hs = double_sha256_strings(&hs_vec);
        //println!("hash sequence:{}", hs);
        hs
    }
    pub fn hash_output_calculator(&self) -> String {
        let mut hash_output: Vec<String> = Vec::new(); 
        for vout in &self.vout {
            let scriptpubkey_bytes = hex::decode(vout["scriptpubkey"].as_str().unwrap()).unwrap();
            let scriptpubkey_size_hex = format!("{:02x}", scriptpubkey_bytes.len() as u8);
            let scriptpubkey_hex = hex::encode(&scriptpubkey_bytes);
            let vout_value = vout["value"].as_u64().unwrap();
            let mut value_bytes = [0; 8]; // 8 bytes for a u64 value
            LittleEndian::write_u64(&mut value_bytes, vout_value);
            let value_bytes_hex = format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",value_bytes[0], value_bytes[1], value_bytes[2], value_bytes[3],value_bytes[4], value_bytes[5], value_bytes[6], value_bytes[7]);
            let vout_message = format!("{}{}{}", value_bytes_hex, scriptpubkey_size_hex, scriptpubkey_hex);
            hash_output.push(vout_message);
        }
        let ho_vec: Vec<&str> = hash_output.iter().map(|s| s.as_str()).collect();
        let ho = double_sha256_strings(&ho_vec);
        //println!("hash prevout:{}", ho);
        ho
    }
    pub fn p2wpkh_transaction_maker(&self, wtxid: bool) -> String {
          //Version number
          let version_bytes = self.version.to_le_bytes().iter().map(|&b| format!("{:02x}", b)).collect::<String>();
          /// Locktime 
          let locktime_hex = self.locktime.to_le_bytes().iter().map(|&b| format!("{:02x}", b)).collect::<String>();
          //println!("{}",locktime_hex);
          //marker and flag
          let marker = "00";
          let flag = "01";
          

          let mut vin_messages = vec![];

          let mut inputcount = 0; 
          for vin in &self.vin {
            //Txid
            let txid_bytes_reversed = hex::encode(&hex::decode(vin["txid"].as_str().unwrap()).unwrap().into_iter().rev().collect::<Vec<_>>());
            //Vout bytes
            let vout_value = vin["vout"].as_u64().unwrap() as u32;
            let mut vout_bytes = [0; 4];
            LittleEndian::write_u32(&mut vout_bytes, vout_value);
            let vout_bytes_hex = format!("{:02x}{:02x}{:02x}{:02x}", vout_bytes[0], vout_bytes[1], vout_bytes[2], vout_bytes[3]);
            //Segwit does not have script sig
            let script_sig_size = "00";
            //Sequence
            let sequence_num = vin["sequence"].as_u64().unwrap();
            let sequence_num = vin["sequence"].as_u64().unwrap() as u32;
            let mut sequence_num_bytes = [0; 4]; // 4 bytes for a u32 value
            LittleEndian::write_u32(&mut sequence_num_bytes, sequence_num);
            let sequence_num_bytes_hex = format!("{:02x}{:02x}{:02x}{:02x}", sequence_num_bytes[0], sequence_num_bytes[1], sequence_num_bytes[2], sequence_num_bytes[3]);
            //vin message
            let mut vin_message = String::new();
            vin_message = format!("{}{}{}{}", txid_bytes_reversed, vout_bytes_hex, script_sig_size, sequence_num_bytes_hex);
            vin_messages.push(vin_message);
            inputcount += 1;
        }
         //println!("{}",scriptpubkey_asm);
        let inputcount_hex = format!("{:02x}", inputcount as u8);

        //Output section
        let mut output_count = 0;
        let mut vout_messages = vec![];
        for vout in &self.vout {
            let scriptpubkey_bytes = hex::decode(vout["scriptpubkey"].as_str().unwrap()).unwrap();
            let scriptpubkey_size_hex = format!("{:02x}", scriptpubkey_bytes.len() as u8);
            let scriptpubkey_hex = hex::encode(&scriptpubkey_bytes);
            let vout_value = vout["value"].as_u64().unwrap();
            let mut value_bytes = [0; 8]; // 8 bytes for a u64 value
            LittleEndian::write_u64(&mut value_bytes, vout_value);
            let value_bytes_hex = format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",value_bytes[0], value_bytes[1], value_bytes[2], value_bytes[3],value_bytes[4], value_bytes[5], value_bytes[6], value_bytes[7]);
            let vout_message = format!("{}{}{}", value_bytes_hex, scriptpubkey_size_hex, scriptpubkey_hex);
            vout_messages.push(vout_message);
            output_count += 1;
        }
        let output_count_hex = format!("{:02x}", output_count as u8);

        //witness section
        let mut witness_messages = vec![];
        for vin in &self.vin {
            let mut witness_arr: Vec<String> = Vec::new();
            if let Some(witness) = vin["witness"].as_array() {
               witness_arr = witness
               .iter()
               .map(|w| w.as_str().unwrap_or_default().to_string())
               .collect();
            }
            let pubkey = witness_arr.get(1).unwrap();
            let signature = witness_arr.get(0).unwrap();
            let pubkey_size = format!("{:02x}", hex::decode(pubkey).unwrap().len() as u8);
            let signature_size = format!("{:02x}", hex::decode(signature).unwrap().len() as u8);
            let witness_message = format!("{}{}{}{}{}","02",signature_size,signature,pubkey_size,pubkey);
            witness_messages.push(witness_message);
        }
        let mut raw_transaction = String::new();

        if wtxid {
            raw_transaction = format!("{}{}{}{}{}{}{}{}{}", version_bytes,marker,flag,inputcount_hex,vin_messages.join(""),output_count_hex,vout_messages.join(""),witness_messages.join(""),locktime_hex);
        } else {
            raw_transaction = format!("{}{}{}{}{}{}", version_bytes,inputcount_hex,vin_messages.join(""),output_count_hex,vout_messages.join(""),locktime_hex);
        }
        //println!("Raw transaction: {}",raw_transaction);

         // First, decode the raw_transaction into bytes
        let raw_bytes = hex::decode(raw_transaction).unwrap_or_else(|err| {
            panic!("Error decoding hex string: {}", err);
        });

        // Calculate the double SHA256 hash
        let txid = double_sha256(&raw_bytes);
        //Little endian of txid or reversed
        let txid_hex = hex::encode(&txid.iter().rev().copied().collect::<Vec<u8>>());
        
        if wtxid{
             txid_hex
        } else{
             txid_hex
        }
     
          
    }
}
