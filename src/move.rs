use sha2::{Digest, Sha256};

fn main() {
    let version = 1;
    let version_bytes = version.to_le_bytes();

    let prevout_tx = "d1283ec7f6a2bcb65a5905033168258ca282e806c9dc7164415519a5ef041b14";
    let bytes_reversed = hex::decode(prevout_tx).unwrap().into_iter().rev().collect::<Vec<_>>();
    let hex_le = hex::encode(bytes_reversed);

    let inputcoin = 1;
    let inputcoin_hex = inputcoin.to_le_bytes();

    let prev_output_index = 0;
    let prev_output_index_hex = prev_output_index.to_le_bytes();

    let scriptpubkey = "76a91496bc8310635539000a65a7cc95cb773c0cc7009788ac";
    let scriptpubkey_bytes = hex::decode(scriptpubkey).unwrap();

    let sequence_num = 4294967295;
    let sequence_num_bytes = sequence_num.to_le_bytes();

    let output_count = 1;
    let output_count_bytes = output_count.to_le_bytes();

    let satoshis = 1100665;
    let satoshis_bytes = satoshis.to_le_bytes();

    let output_scriptpubkey = "76a914e5977cf916acdba010b9d847b9682135aa3ea81a88ac";
    let output_scriptpubkey_bytes = hex::decode(output_scriptpubkey).unwrap();

    let locktime = 0;
    let locktime_bytes = locktime.to_le_bytes();

    let sighash_type = "01000000";

    // Concatenate all the byte arrays
    let mut message = vec![];
    message.extend_from_slice(&version_bytes);
    message.extend_from_slice(&inputcoin_hex);
    message.extend_from_slice(hex::decode(hex_le).unwrap().as_slice());
    message.extend_from_slice(&prev_output_index_hex);
    message.push(scriptpubkey_bytes.len() as u8);
    message.extend_from_slice(scriptpubkey_bytes.as_slice());
    message.extend_from_slice(&sequence_num_bytes);
    message.extend_from_slice(&output_count_bytes);
    message.extend_from_slice(&satoshis_bytes);
    message.push(output_scriptpubkey_bytes.len() as u8);
    message.extend_from_slice(output_scriptpubkey_bytes.as_slice());
    message.extend_from_slice(&locktime_bytes);
    message.extend_from_slice(hex::decode(sighash_type).unwrap().as_slice());

    let hash = Sha256::digest(&Sha256::digest(&message));
    let hash_hex = hex::encode(hash);
    println!("{}", hash_hex);
}