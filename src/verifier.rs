extern crate hex;

use secp256k1::{Secp256k1, PublicKey, Message};
use hex::decode;
use sha2::{Sha256,Digest};
use secp256k1::ecdsa::Signature;

fn double_sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(&Sha256::digest(data)).to_vec()
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

fn main() {
    // Define the signature, public key, and message
    let signature_hex = "30440220200b9a61529151f9f264a04e9aa17bb6e1d53fb345747c44885b1e185a82c17502200e41059f8ab4d3b3709dcb91b050c344b06c5086f05598d62bc06a8b746db429";
    let public_key_hex = "025f0ba0cdc8aa97ec1fffd01fac34d3a7f700baf07658048263a2c925825e8d33";
    let message_hex = "0100000001141b04efa51955416471dcc906e882a28c2568310305595ab6bca2f6c73e28d1000000001976a91496bc8310635539000a65a7cc95cb773c0cc7009788acffffffff0179cb1000000000001976a914e5977cf916acdba010b9d847b9682135aa3ea81a88ac0000000001000000";

    if verify_ecdsa_signature(signature_hex, public_key_hex, message_hex) {
        println!("Signature is Valid");
    } else {
        println!("Signature is not Valid");
    }
    println!("Verifier file usef individually");
}