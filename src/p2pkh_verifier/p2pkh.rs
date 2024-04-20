use serde_json::Value;
use std::fs;
use sha2::{Digest, Sha256};
use byteorder::{ByteOrder, LittleEndian};
extern crate hex;
use secp256k1::{Secp256k1, PublicKey, Message};
use hex::decode;
use secp256k1::ecdsa::Signature;
use ripemd::Ripemd160;

pub struct P2PKH {
    vin: Vec<Value>,
    vout: Vec<Value>,
    version: u32,
    locktime: u32,
}


pub fn p2pkh_verifier(folder_path: &str) -> Vec<std::string::String>{
    let mut number_of_transactions_processed = 0;
    let mut number_of_valid_txn=0;
    let mut number_of_invalid_txn = 0;
    let mut number_of_multi_script_types=0;
    let mut txid_vec: Vec<String> = Vec::new();
    if let Ok(entries) = fs::read_dir(folder_path) {
        for entry in entries {
            if let Ok(entry) = entry {
                let file_path = entry.path();
                if let Ok(file_content) = fs::read_to_string(&file_path) {
                    if let Ok(data) = serde_json::from_str::<Value>(&file_content) {
                        
                        if let Some(vin) = data["vin"].as_array() {
                            let mut flag = true;
                            //Checking if the same transaction contains different script types other than p2pkh
                            for vin_entry in vin {
                                if let (Some(scriptsig_asm), Some(prevout), Some(scriptpubkey_asm)) = (vin_entry["scriptsig_asm"].as_str(), vin_entry["prevout"].as_object(), vin_entry["prevout"]["scriptpubkey_asm"].as_str()) {
                                    if prevout["scriptpubkey_type"].as_str() != Some("p2pkh") {
                                        flag = false;
                                        break;
                                    }
                                }
                            }
                            if flag {
                                number_of_transactions_processed+=1;
                                let p2pkh_object = P2PKH::new(&data);
                                let result = p2pkh_object.validator();
                                let mut txid: String = String::new();
                                if result {
                                    number_of_valid_txn+=1;
                                   // println!("Validtxn");
                                    //extract and make the transaction id of valid legacy transactions
                                    txid_vec.push(p2pkh_object.p2pkh_transaction_maker());
                                   
                                }else{
                                    number_of_invalid_txn+=1;
                                    //println!("Invalid txn")
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
    //println!("{:?}", txid_vec);
    println!("Number of transactions processed: {}", number_of_transactions_processed);
    println!("Number of valid transactions: {}", number_of_valid_txn);
    println!("Number of invalid transactions: {}", number_of_invalid_txn);
    println!("Number of transactions with multiple script types: {}", number_of_multi_script_types);

    return txid_vec;

}

// computes merkel root of vector of strings and returns in reverse byte order
fn merkle_root(txids: Vec<&str>) -> String {
    // Convert txids to little-endian byte order

    // Reverse byte order and convert to little-endian
    let txids_le: Vec<String> = txids.iter().map(|txid| {
        let txid_bytes = hex::decode(txid).unwrap().into_iter().rev().collect::<Vec<_>>();
        hex::encode(txid_bytes)
    }).collect();

    println!("{:?}", txids_le);
    // Recursive function to compute Merkle root
    fn compute_merkle_root(txids: Vec<String>) -> String {
        if txids.len() == 1 {
            return txids[0].clone();
        }

        let mut result = Vec::new();

        for pair in txids.chunks(2) {
            let concat = match pair.len() {
                2 => pair[0].clone() + &pair[1],
                1 => pair[0].clone() + &pair[0],
                _ => panic!("Unexpected length in pair"),
            };
        //println!("{}",concat);
        result.push(double_sha256(hex::decode(&concat).unwrap().as_slice()).iter().map(|&byte| format!("{:02x}", byte)).collect::<String>());

        }

        compute_merkle_root(result)
    }

    // Call recursive function to compute Merkle root
    let merkle_root = compute_merkle_root(txids_le);

    // Convert Merkle root to reverse order
    hex::encode(&hex::decode(&merkle_root.as_str()).unwrap().into_iter().rev().collect::<Vec<_>>())
   
}

fn double_sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(&Sha256::digest(data)).to_vec()
}
fn p2pkh_script_verifier(scriptpubkey_asm: &str, public_key: &str) -> bool {
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
     hex::encode(&pkh_bytes) == arr[3]
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

impl P2PKH {
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
       
        for vin in &self.vin {
            
            let valid = self.validate_vin(vin_number);
            
            if !valid {
                return false;
            }
            vin_number += 1;
        }
        true
    }

    pub fn validate_vin(&self, vin_number: usize) -> bool {
        let version_bytes = self.version.to_le_bytes().iter().map(|&b| format!("{:02x}", b)).collect::<String>();
   
        let mut inputcount = 0;
        let mut vin_messages = vec![];
        let mut scriptpubkey_asm = "";
        let mut scriptsig_asm = String::new();
        
        for vin in &self.vin {
            let txid_bytes_reversed = hex::encode(&hex::decode(vin["txid"].as_str().unwrap()).unwrap().into_iter().rev().collect::<Vec<_>>());
            let vout_value = vin["vout"].as_u64().unwrap() as u32;
            let mut vout_bytes = [0; 4];
            LittleEndian::write_u32(&mut vout_bytes, vout_value);
            let vout_bytes_hex = format!("{:02x}{:02x}{:02x}{:02x}", vout_bytes[0], vout_bytes[1], vout_bytes[2], vout_bytes[3]);
            let prev_output_scriptpubkey_bytes = hex::decode(vin["prevout"]["scriptpubkey"].as_str().unwrap()).unwrap();
            let scriptpubkey_size_hex = format!("{:02x}", prev_output_scriptpubkey_bytes.len() as u8);
            let scriptpubkey_hex = hex::encode(&prev_output_scriptpubkey_bytes);
            let sequence_num = vin["sequence"].as_u64().unwrap();
            let sequence_num = vin["sequence"].as_u64().unwrap() as u32;
            let mut sequence_num_bytes = [0; 4]; // 4 bytes for a u32 value
            LittleEndian::write_u32(&mut sequence_num_bytes, sequence_num);
            let sequence_num_bytes_hex = format!("{:02x}{:02x}{:02x}{:02x}", sequence_num_bytes[0], sequence_num_bytes[1], sequence_num_bytes[2], sequence_num_bytes[3]);
            
            let mut vin_message = String::new();
            if inputcount == vin_number {
                scriptsig_asm = (vin["scriptsig_asm"].as_str().unwrap()).to_string();
                scriptpubkey_asm = (vin["prevout"]["scriptpubkey_asm"].as_str().unwrap());
                vin_message = format!("{}{}{}{}{}", txid_bytes_reversed, vout_bytes_hex, scriptpubkey_size_hex, scriptpubkey_hex, sequence_num_bytes_hex);
            } else {
                let script_size = format!("{:02x}", 0 as u8);
                vin_message = format!("{}{}{}{}", txid_bytes_reversed, vout_bytes_hex, script_size, sequence_num_bytes_hex);
            };

            vin_messages.push(vin_message);

            inputcount += 1;
        }
         //println!("{}",scriptpubkey_asm);
        let inputcount_hex = format!("{:02x}", inputcount as u8);
                
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

        let sighashall = "01000000";

        let output_count_hex = format!("{:02x}", output_count as u8);
      
        let message = format!("{}{}{}{}{}{}{}", version_bytes, inputcount_hex, vin_messages.join(""), output_count_hex, vout_messages.join(""), self.locktime.to_le_bytes().iter().map(|&b| format!("{:02x}", b)).collect::<String>(), sighashall);

        //println!("{}\n", message);

        //use the scriptsig_asm and split it to extract signature and public_key
        let arr:Vec<&str> = scriptsig_asm.split(" ").collect();
        
        let mut signature = arr[1];
        let new_signature = &signature[..signature.len() - 2];
        //println!("{}", &signature[signature.len() - 2..]);
        let mut public_key = arr[3];
        
        ////////////////////////////////////////////////////////////////
        /// I am not considering transaction other than sighashall so the function returns false
        if &signature[signature.len() - 2..] != "01" {
            println!("not sighashall type signature");
            return false;
        }
        //Checking that public key is equal to public key hash
        if !p2pkh_script_verifier(scriptpubkey_asm, public_key){
            return false
        }

        let check = verify_ecdsa_signature(&new_signature, &public_key , &message );

        check
        //println!("{}\n", check);
     
    }

    pub fn p2pkh_transaction_maker(self) -> String{
        let version_bytes = self.version.to_le_bytes().iter().map(|&b| format!("{:02x}", b)).collect::<String>();
   
        let mut inputcount = 0;
        let mut vin_messages = vec![];
        let mut scriptpubkey_asm = "";
        let mut scriptsig_asm = String::new();

        for vin in &self.vin {
            //Txid
            let txid_bytes_reversed = hex::encode(&hex::decode(vin["txid"].as_str().unwrap()).unwrap().into_iter().rev().collect::<Vec<_>>());
            //Vout bytes
            let vout_value = vin["vout"].as_u64().unwrap() as u32;
            let mut vout_bytes = [0; 4];
            LittleEndian::write_u32(&mut vout_bytes, vout_value);
            let vout_bytes_hex = format!("{:02x}{:02x}{:02x}{:02x}", vout_bytes[0], vout_bytes[1], vout_bytes[2], vout_bytes[3]);
            
            //Script_sig 
            let prev_output_scriptsig_bytes = hex::decode(vin["scriptsig"].as_str().unwrap()).unwrap();
            let scriptsig_size_hex = format!("{:02x}", prev_output_scriptsig_bytes.len() as u8);
            let scriptsig_hex = hex::encode(&prev_output_scriptsig_bytes);

            //Sequence
            let sequence_num = vin["sequence"].as_u64().unwrap();
            let sequence_num = vin["sequence"].as_u64().unwrap() as u32;
            let mut sequence_num_bytes = [0; 4]; // 4 bytes for a u32 value
            LittleEndian::write_u32(&mut sequence_num_bytes, sequence_num);
            let sequence_num_bytes_hex = format!("{:02x}{:02x}{:02x}{:02x}", sequence_num_bytes[0], sequence_num_bytes[1], sequence_num_bytes[2], sequence_num_bytes[3]);
            

            //vin message
            let mut vin_message = String::new();
            vin_message = format!("{}{}{}{}{}", txid_bytes_reversed, vout_bytes_hex, scriptsig_size_hex, scriptsig_hex, sequence_num_bytes_hex);
            vin_messages.push(vin_message);
            inputcount += 1;
          
        }
         //println!("{}",scriptpubkey_asm);
        let inputcount_hex = format!("{:02x}", inputcount as u8);


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
      
        let raw_transaction = format!("{}{}{}{}{}{}", version_bytes, inputcount_hex, vin_messages.join(""), output_count_hex, vout_messages.join(""), self.locktime.to_le_bytes().iter().map(|&b| format!("{:02x}", b)).collect::<String>());

        //println!("The raw transaction is:{}\n", raw_transaction);

        // First, decode the raw_transaction into bytes
        let raw_bytes = hex::decode(raw_transaction).unwrap_or_else(|err| {
            panic!("Error decoding hex string: {}", err);
        });
        // Calculate the double SHA256 hash
        let txid = double_sha256(&raw_bytes);
        //Little endian of txid
        let txid_hex = hex::encode(&txid.iter().rev().copied().collect::<Vec<u8>>());
        return txid_hex;

   }
}