## DESIGN APPROACH

Here is my design approach divided into three main parts:

### (1) Block Mining and Output approach

#### Transaction Verification:

- Runs `p2pkh_verifier` and `p2wpkh_verifier` functions to verify transactions in the specified directories (`"./mempool"`).
- Collects transaction IDs (`txid_vec`) from `p2pkh_verifier` and transaction IDs along with witness transaction IDs (`txid_vec` and `wtxid_vec`) from `p2wpkh_verifier`.

#### Witness Commitment:

- Generates a witness commitment using `witness_commitment_maker` with `p2pkh_txid_vec` and `p2wpkh_wtxid_vec`.

#### Coinbase Transaction Generation:

- Creates a coinbase transaction and its serialized form using `coinbase_txid_maker` with the witness commitment.
- Stores the coinbase transaction ID (`coinbase_txn`) and its serialized form (`coinbase_serialized`).

#### Block Header Preparation:

- Prepares the components of a block header:
  - Version (`version`)
  - Previous Block Hash (`previous_block`)
  - Merkel Root (using `merkel_root_calculator` with `p2pkh_txid_vec`, `p2wpkh_txid_vec`, and `coinbase_txn`)
  - Timestamp (`time`)
  - Target (`target_str` and `compact_target_value`)

#### Transaction Concatenation:

- Combines the coinbase transaction, P2PKH transaction IDs, and P2WPKH transaction IDs into a single `transactions` vector.

#### Block Header Serialization:

- Constructs the block header without the nonce (`block_header_without_nonce`) by concatenating the block header components.

#### Mining:

- Initializes the nonce (`nonce`) to zero.
- Attempts to mine a block by continuously incrementing the nonce until a block hash below the target is found.
- Serializes the block header with the current nonce and calculates the hash.
- Compares the hash with the target to determine if the block is valid.
- Breaks the loop and finalizes the block header once a valid block hash is found.

#### Output File Creation:

- Creates or opens the `output.txt` file.
- Writes the block header, coinbase transaction, and transaction data (coinbase and individual transactions) into the output file, each line representing a different component.

### (2) P2PKH Verification

#### Input Processing:

- Reads transaction data from files in a specified folder.
- Parses JSON data to extract relevant fields such as `vin` (input transactions) and `vout` (output transactions).

#### Transaction Validation:

- Checks if the transaction script type is P2PKH (Pay-to-Public-Key-Hash).
- Verify each input in the transaction using the P2PKH validation logic.
- Validate the script signature and public key against the input transaction details.

#### Public Key Hash Verification:

- Calculates the public key hash from the provided public key using SHA-256 and RIPEMD-160 hashing algorithms.
- Compares the calculated public key hash with the script's public key hash to verify ownership.

#### ECDSA Signature Verification:

- Decode the ECDSA signature and public key from hexadecimal strings.
- Hash the message using double SHA-256.
- Verify the ECDSA signature against the hashed message and public key using the secp256k1 library.

#### Transaction Creation (for valid P2PKH transactions):

- Construct a raw transaction based on input and output details.
- Encode the raw transaction into hexadecimal format.
- Calculate the double SHA-256 hash of the raw transaction to generate the transaction ID (TxID).

### (3) P2WPKH Verification

#### Parsing Transactions:

- Reads transactions from a specified folder.
- Parses the JSON content of each transaction file.
- Checks if the file size is within a limit of 90 KB.

#### Filtering Script Types:

- Identifies transactions with P2PKH scripts (`v0_p2wpkh`) in the input scripts (`vin`).
- Skips transactions with different script types.

#### Hash Calculations:

- Calculates various hashes required for validation:
  - `hash_prevouts` -> concatenation of `txid` and `vout` of all prevout transactions then double SHA-256 hash
  - `hash_sequence` -> concatenation of all the sequence of all prevout then double SHA-256 hash
  - `hash_outputs` -> concatenation of value, scriptpubkey size, and script pubkey for all `vout` transactions then double SHA-256 hash

#### Transaction Validation:

- Creates a P2WPKH object for each valid transaction.
- Calls the validator method of the P2WPKH object for validation.

#### Signature Verification:

- Inside the `validate_vin` method of P2WPKH, verifies ECDSA signatures using the provided public key and message.

#### Transaction Construction:

- Constructs the raw transaction using input and output data.
- Double SHA256 hashes the raw transaction to obtain the transaction ID (`txid`).
- Includes witness data for segregated witness transactions (`wtxid`).




#### IMPLEMENTAION DETAILS


#### RESULTS AND PERFORMANCE

#### CONCLUSION

