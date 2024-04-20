use serde_json::Value;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;





// fn checker(scriptsig_asm: &str, scriptpubkey_asm: &str) -> bool {
//     let pub_key = scriptsig_asm.split_whitespace().last().unwrap();
//     let pkh = hash160(pub_key);
//     let pkh_real = scriptpubkey_asm.split_whitespace().nth(3).unwrap();
//     pkh_real == pkh
// }

fn main() {
    let mempool_folder_path = "/home/archit/Desktop/rust/rustverifier/code-challenge-2024-Minimega12121-main/mempool";
    let output_folder_base = "/home/archit/Desktop/rust/rustverifier/code-challenge-2024-Minimega12121-main";

    // Iterate through all files in the mempool folder
    for entry in fs::read_dir(mempool_folder_path).expect("Failed to read directory") {
        if let Ok(entry) = entry {
            let file_path = entry.path();
            if let Some(file_name) = file_path.file_name().and_then(|name| name.to_str()) {
                if file_name.ends_with(".json") {
                    // Read and parse the JSON file
                    let mut file = File::open(&file_path).expect("Failed to open file");
                    let mut contents = String::new();
                    file.read_to_string(&mut contents).expect("Failed to read file");
                    let data: Value = serde_json::from_str(&contents).expect("Failed to parse JSON");

                    // Extract data["vin"][0]["prevout"]["scriptpubkey_type"]
                    if let Some(vin_array) = data["vin"].as_array() {
                        if let Some(vin) = vin_array.get(0) {
                            if let Some(prevout) = vin["prevout"].as_object() {
                                if let Some(scriptpubkey_type) = prevout["scriptpubkey_type"].as_str() {
                                    // Create folder based on scriptPubKey type
                                    let output_folder = PathBuf::from(output_folder_base).join(scriptpubkey_type);
                                    fs::create_dir_all(&output_folder).expect("Failed to create directory");

                                    // Copy the JSON file to the corresponding folder
                                    let output_file_path = output_folder.join(file_name);
                                    fs::copy(&file_path, &output_file_path).expect("Failed to copy file");

                                }
                            }
                        }
                    }
                }
            }
        }
    }



    let mempool_folder_path = "/home/archit/Desktop/rust/rustverifier/code-challenge-2024-Minimega12121-main/p2pkh";

    // Iterate through all files in the mempool folder
    for entry in fs::read_dir(mempool_folder_path).expect("Failed to read directory") {
        if let Ok(entry) = entry {
            let file_path = entry.path();
            if let Some(file_name) = file_path.file_name().and_then(|name| name.to_str()) {
                if file_name.ends_with(".json") {
                    // Read the JSON file
                    let mut file = File::open(&file_path).expect("Failed to open file");
                    let mut contents = String::new();
                    file.read_to_string(&mut contents).expect("Failed to read file");
                    let data: serde_json::Value = serde_json::from_str(&contents).expect("Failed to parse JSON");
                    // Parse JSON into a serde_json::Value or your custom struct
                    // Add your desired functionality here
                    // For example:
                    // let data: serde_json::Value = serde_json::from_str(&contents).expect("Failed to parse JSON");
                    // println!("{:?}", data);
                    let version = data["version"].as_u64().unwrap();
                    println!("{}",version);

                    if let Some(vin_array) = data["vin"].as_array(){
                        if let Some(vin) = vin_array.get(0) {
                            let scriptsig_asm = vin["scriptsig_asm"].as_str().unwrap();
                            println!("{}",scriptsig_asm);
                            let scriptpubkey_asm = vin["prevout"]["scriptpubkey_asm"].as_str().unwrap();
                            println!("{}",scriptpubkey_asm);
                        }
                    }
                }
            }
        }
    }


}
