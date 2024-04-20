use serde_json::Value;
use std::fs;
use sha2::{Digest, Sha256};
use byteorder::{ByteOrder, LittleEndian};
extern crate hex;
use secp256k1::{Secp256k1, PublicKey, Message};
use hex::decode;
use secp256k1::ecdsa::Signature;
use ripemd::Ripemd160;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};
// Calling p2pkh and p2wpkh modules
mod p2pkh_verifier;
use p2pkh_verifier::p2pkh::p2pkh_verifier ;
mod p2wpkh_verifier;
use p2wpkh_verifier::p2wpkh::p2wpkh_verifier ;
use std::fs::File;
use std::io::{self, Write};
use chrono::{DateTime, NaiveDateTime, Utc};
use num_bigint::BigUint;
use num_traits::{FromPrimitive, Num, ToPrimitive};
use std::convert::TryInto;
use std::str::FromStr;


// computes merkel root of vector of strings and returns in reverse byte order
fn merkle_root(txids: Vec<&str>) -> String {
    // Convert txids to little-endian byte order

    // Reverse byte order and convert to little-endian
    let txids_le: Vec<String> = txids.iter().map(|txid| {
        let txid_bytes = hex::decode(txid).unwrap().into_iter().rev().collect::<Vec<_>>();
        hex::encode(txid_bytes)
    }).collect();

   // println!("{:?}", txids_le);
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

//Function used to calculate hashPrevouts,Outputs and Sequence
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


//fn coinbase_transaction_maker
fn witness_root_hash_maker(p2pkh_txid_vec: Vec<String>, p2wpkh_wtxid_vec: Vec<String>) -> String {
    let mut combined_txids: Vec<&str> = Vec::new();

    // Add wtxid of coinbase transaction
    combined_txids.push("0000000000000000000000000000000000000000000000000000000000000000");

    // Extend combined_txids with p2pkh_txid_vec
    combined_txids.extend(p2pkh_txid_vec.iter().map(|s| s.as_str()));

    // Extend combined_txids with p2wpkh_wtxid_vec
    combined_txids.extend(p2wpkh_wtxid_vec.iter().map(|s| s.as_str()));


    // Return the witness root hash as a String
    
    merkle_root(combined_txids)
}
fn witness_commitment_maker(p2pkh_txid_vec: Vec<String>, p2wpkh_wtxid_vec: Vec<String>) -> String{
    let mut witness_root_hash = witness_root_hash_maker(p2pkh_txid_vec, p2wpkh_wtxid_vec);
    //revrese this
    witness_root_hash = hex::encode(&hex::decode(&witness_root_hash.as_str()).unwrap().into_iter().rev().collect::<Vec<_>>());
    //println!("witness_root_hash :{}", witness_root_hash);
    let witness_reserve_value = "0000000000000000000000000000000000000000000000000000000000000000".to_string();

    // Concatenate witness_root_hash and witness_reserve_value
    let combined_string = witness_root_hash + &witness_reserve_value.to_string() ;
    let temp = decode(combined_string).expect("Witness commitment not decoded correctly");
    let witness_commitment = double_sha256(&temp);
    //println!("The witness commitment is:{}", hex::encode(witness_commitment.clone()));
    hex::encode(witness_commitment)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn merkel_root_checker () {
        let txids = vec![
            "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
            "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
            "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
            "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d"
        ];

        let merkle_root = merkle_root(txids);
        //println!("Merkel root is : {}", merkle_root);
        assert_eq!(merkle_root,"f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766");
    }
    fn test_p2pkh_script_verifier() {
        let scriptpubkey_asm = "OP_DUP OP_HASH160 OP_PUSHBYTES_20 4cf014394e1aa81ca0317ad24c3a886040e80da7 OP_EQUALVERIFY OP_CHECKSIG";
        let public_key = "02e57d639eb8ad9feeda51d951c33feed17c2ad7946c3a7223513fb912a5b2363b";
        assert_eq!(p2pkh_script_verifier(scriptpubkey_asm, public_key), true);
    }
    #[test]
    fn hash_previous_outpoints() {
        let strings = vec![
            "ed204affc7519dfce341db0569687569d12b1520a91a9824531c038ad62aa9d1",
            "01000000",
            "9cb872539fbe1bc0b9c5562195095f3f35e6e13919259956c6263c9bd53b20b7",
            "01000000",
            "8012f1ec8aa9a63cf8b200c25ddae2dece42a2495cc473c1758972cfcd84d904",
            "01000000",
        ];
        let result_hex = double_sha256_strings(&strings);
        //println!("{}", result_hex);
        assert_eq!(result_hex,"99197e88ff743aff3e453e3a7b745abd31937ccbd56f96a179266eba786833e6")
    }
    #[test]
    fn witness_commitment_maker_test(){
        let p2pkh_txid:Vec<String> = vec!["8700d546b39e1a0faf34c98067356206db50fdef24e2f70b431006c59d548ea2".to_string()];
        let p2wpkh_wtxid:Vec<String>  = vec!["c54bab5960d3a416c40464fa67af1ddeb63a2ce60a0b3c36f11896ef26cbcb87".to_string(),
        "e51de361009ef955f182922647622f9662d1a77ca87c4eb2fd7996b2fe0d7785".to_string()];
        assert_eq!(witness_commitment_maker(p2pkh_txid, p2wpkh_wtxid),"6502e8637ba29cd8a820021915339c7341223d571e5e8d66edd83786d387e715".to_string() );
    }
}

fn coinbase_txid_maker( witness_commitment: String)-> (String, String) {
    let starting = "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2503233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100ffffffff";
    let output_count = "02";
    let amount = "0000000000000000";

    // let block_height: u32 = 900000; // Specify the type explicitly
    // let block_height_bytes = block_height.to_le_bytes(); // Converts to little-endian bytes
    // let block_height_hex = format!("{:06X}", u32::from_le_bytes(block_height_bytes)); // Convert bytes to hexadecimal string with leading zeros and 6 characters
    // println!("Block Height in Little Endian Hex: {}", block_height_hex);

    // let mut script_pub_key = String::from("30a0bb0d");
    // script_pub_key+= "18";
    // script_pub_key += "4d696e656420627920416e74506f6f6c373946205b8160a4";
    // script_pub_key+= "25";
    // script_pub_key += "6c0000946e0100";//extranonce
    let mut script_pub_key =String::from("19");
    script_pub_key+="76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac";

    //witness_commitment section
    let mut second_output = String::from("0000000000000000");
    second_output+="26";
    second_output+= "6a24aa21a9ed";
    second_output+= &witness_commitment;
    
    //witness section
    let witness = "01200000000000000000000000000000000000000000000000000000000000000000";
    //
    let locktime = "00000000";


    // println!("Starting: {}", starting);
    // println!("Output Count: {}", output_count);
    // println!("Amount: {}", amount);
    // println!("Script Pub Key: {}", script_pub_key);
    // println!("Second Output: {}", second_output);
    // println!("Witness: {}", witness);


    let coinbase_txid = format!("{}{}{}{}{}{}{}", starting, output_count, amount, script_pub_key, second_output, witness, locktime);
    println!("Coinbase txid is:{}", coinbase_txid);
    // First, decode the raw_transaction into bytes
    let raw_bytes = hex::decode(coinbase_txid.clone()).unwrap_or_else(|err| {
        panic!("Error decoding hex string: {}", err);
    });
    // Calculate the double SHA256 hash
    let txid = double_sha256(&raw_bytes);
    //Little endian of txid
    let txid_hex = hex::encode(&txid.iter().rev().copied().collect::<Vec<u8>>());
    (txid_hex, coinbase_txid)
}

fn merkel_root_calculator(p2pkh_txid_vec: Vec<String>, p2wpkh_txid_vec: Vec<String> , coinbase_txid: String)-> String{
    let mut combined_txids: Vec<&str> = Vec::new();

    // Add wtxid of coinbase transaction
    combined_txids.push(coinbase_txid.as_str());

    // Extend combined_txids with p2pkh_txid_vec
    combined_txids.extend(p2pkh_txid_vec.iter().map(|s| s.as_str()));

    // Extend combined_txids with p2wpkh_wtxid_vec
    combined_txids.extend(p2wpkh_txid_vec.iter().map(|s| s.as_str()));

    // Return the witness root hash as a String
    merkle_root(combined_txids)
    
}   

fn main() {
    // Create an Instant to mark the starting time
    let start_time = Instant::now();

    let p2pkh_path = "./mempool";
    let p2pkh_txid_vec = p2pkh_verifier(p2pkh_path);

    let p2wpkh_path = "./mempool";
    let (p2wpkh_txid_vec, p2wpkh_wtxid_vec ) = p2wpkh_verifier(p2wpkh_path);

    let transaction_count = p2wpkh_txid_vec.len() + p2pkh_txid_vec.len() + 1;//add one for coinbase transaction

    let witness_commitment = witness_commitment_maker(p2pkh_txid_vec.clone(), p2wpkh_wtxid_vec);

    println!("{}", witness_commitment);

    let (coinbase_txn,coinbase_serialized) = coinbase_txid_maker(witness_commitment);
    println!("coinbase txid:{}", coinbase_txn);
    //println!("010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2503233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100ffffffff02f595814a000000001976a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac0000000000000000266a24aa21a9edfaa194df59043645ba0f58aad74bfd5693fa497093174d12a4bb3b0574a878db0120000000000000000000000000000000000000000000000000000000000000000000000000");
    
    //Block header
    let version = "04000000";
    let previous_block = "0000000000000000000000000000000000000000000000000000000000000000";
    let mut merkel_root = merkel_root_calculator(p2pkh_txid_vec.clone(), p2wpkh_txid_vec.clone(), coinbase_txn.clone());
    merkel_root =  hex::encode(&hex::decode(&merkel_root.as_str()).unwrap().into_iter().rev().collect::<Vec<_>>());
    println!("Merkel root is: {}", merkel_root);
    //Timestamp
    let current_time = SystemTime::now();
    let since_epoch = current_time.duration_since(UNIX_EPOCH).unwrap();
    let timestamp = since_epoch.as_secs() as u32; // Get the Unix timestamp as a u32
    let mut timestamp_num_bytes = [0; 4]; // 4 bytes for a u32 value
    LittleEndian::write_u32(&mut timestamp_num_bytes, timestamp);
    let mut time = format!("{:02x}{:02x}{:02x}{:02x}", timestamp_num_bytes[0], timestamp_num_bytes[1], timestamp_num_bytes[2], timestamp_num_bytes[3]);
    println!("{}", time);




    //Target
    let target_str = "0000ffff00000000000000000000000000000000000000000000000000000000";
    let compact_target_value = "ffff001f"; // Convert to u32 value
    
    println!("Transaction count {}", transaction_count);
    


    //Transactions joined
    let mut transactions : Vec<&str> =  Vec::new();
    transactions.push(coinbase_txn.as_str());
    transactions.extend(p2pkh_txid_vec.iter().map(|s| s.as_str()));
    transactions.extend(p2wpkh_txid_vec.iter().map(|s| s.as_str()));
    let transaction_joined_string = transactions.clone().join("");
    //println!("Transaction: {}", transaction_joined_string);

    let block_header_without_nonce = format!("{}{}{}{}{}",version,previous_block,merkel_root,time,compact_target_value);
    
    println!("Block header: {}",block_header_without_nonce);

    // // Mining 

    let target = BigUint::from_str_radix(&target_str[4..], 16).unwrap(); // Ignore first 4 zeros

    let mut nonce: u32 = 0; // Starting nonce
    let mut block_header =  String::new(); 
    loop {
        // Serialize the block header with the current nonce
        let nonce_bytes = nonce.clone().to_le_bytes().iter().map(|&b| format!("{:02x}", b)).collect::<String>();
        let attempt = format!("{}{}", block_header_without_nonce, nonce_bytes);
        let attempt_bytes = hex::decode(attempt.clone()).unwrap_or_else(|err| {
            panic!("Error decoding hex string: {}", err);
        });
        // Hash the block header twice
        let hash_result = double_sha256(&attempt_bytes);
        let hash_result_hex = hex::encode(&hash_result.iter().rev().copied().collect::<Vec<u8>>());
        let hash_result_byte = decode(hash_result_hex).unwrap();
        // Convert the hash result to BigUint for comparison with the target
        let hash_result_biguint = BigUint::from_bytes_be(hash_result_byte.clone().as_slice());

        // Show the result
        println!("Nonce: {}, Hash: {}", nonce, hex::encode(hash_result));

        // End the loop if we find a block hash below the target
        if hash_result_biguint < target {
            block_header = attempt;
            break;
        }

        // Increment the nonce and try again
        nonce += 1;
    }

    println!("Nonce found: {}", nonce);
    println!("Final header hash:{}", block_header);


    //make output.txt
     // Create or open the output.txt file
     let mut file = File::create("./output.txt").unwrap();

     // Write block header hex
     writeln!(file, "{}", block_header).unwrap();
 
     // Write coinbase transaction hex
     writeln!(file, "{}",coinbase_serialized ).unwrap();
 
     // Write Vec<&str> data line by line
     for item in transactions.iter() {
         writeln!(file, "{}", item).unwrap();
     }



    let elapsed_time = start_time.elapsed();
    // Print the elapsed time in seconds and milliseconds
    //Add transaction ids
    println!("Time taken: {:.2?}", elapsed_time);
    //println!("Fuck you");
    //6b1325c8651def55c38cabfff7335b4519dd9dada4eba0aea5b7114598922137
    //faa194df59043645ba0f58aad74bfd5693fa497093174d12a4bb3b0574a878db
}
trait ToHex {
    fn to_hex(&self) -> String;
}

impl ToHex for [u8] {
    fn to_hex(&self) -> String {
        self.iter()
            .map(|&byte| format!("{:02X}", byte))
            .collect::<Vec<String>>()
            .join("")
    }
}