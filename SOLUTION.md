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




## Implementation Details

### Why only P2PKH and P2WPKH verification ?

For the best optimum solution to get a high score for the assignment, I calculated the max possible value of fee available from different transaction types
On analysis I found that the P2WPKH and P2HWPKH signature verfication would suffice for completion of the assingment.

Other optimization used:
 While reading the mempool a filter is used so that the size of the transaction read is below 90kb, this was done because the time it took to verify and icnlude large 
 transactions were not worth the computational effort
 Apart from this I used a filter to only take the transaction with sighash of type 'sighashall' to simplify the verification process

Following are the algorithm for the three major sections of the solution:

### Block Mining and Output

1. Start a timer (`start_time`) to measure execution time.
2. Run `p2pkh_verifier` and `p2wpkh_verifier` functions to verify transactions in the specified directories.
3. Collect transaction IDs (`p2pkh_txid_vec` and `p2wpkh_txid_vec`) from verifiers.
4. Generate a witness commitment using `witness_commitment_maker` with `p2pkh_txid_vec` and `p2wpkh_wtxid_vec`.
5. Create a coinbase transaction and its serialized form using `coinbase_txid_maker` with the witness commitment.
6. Prepare block header components:
   - Version (`version`)
   - Previous Block Hash (`previous_block`)
   - Merkel Root (calculated using `merkel_root_calculator`)
   - Timestamp (`time`)
   - Target (`target_str` and `compact_target_value`)
7. Combine transactions into a single vector (`transactions`).
8. Serialize the block header without the nonce (`block_header_without_nonce`).
9. Mine the block by incrementing the nonce until a valid hash is found.
10. Create or open `output.txt` and write block header, coinbase transaction, and transactions.

### P2PKH Verification

1. Read transaction data from files and parse JSON content.
2. Check transaction script type for P2PKH.
3. Validate each input using P2PKH logic and ECDSA signature verification.
4. Calculate public key hash and compare with script's public key hash.
5. Construct a raw transaction and calculate its hash to obtain TxID.

### P2WPKH Verification

1. Parse transactions from files and filter by script type.
2. Calculate various hashes required for validation (`hash_prevouts`, `hash_sequence`, `hash_outputs`).
3. Validate transactions using P2WPKH logic and signature verification.
4. Construct raw transactions with witness data and calculate TxID.



#### RESULTS AND PERFORMANCE

Time analysis:
-On an average it takes: 5-8s for p2pkh and p2wpkh transaction verification
Result and score:
- Score: 95
- Fee: 19648217
- Weight: 3801130
- Max Fee: 20616923
- Max Weight: 4000000

#### CONCLUSION

Insights gained from solving this problem include:

Areas for future improvement or research could include:
- Incorporating more types of script-sig types such that the size is even less than the segwit type without compromising security.

Resources used for the project:
- [Learn Me a Bitcoin](https://learnmeabitcoin.com/)
- [Bitcoin Improvement Proposal (BIP) 0143](https://en.bitcoin.it/wiki/BIP_0143)
- [P2PKH Bitcoin Transaction Verifier GitHub Repository](https://github.com/LivioZ/P2PKH-Bitcoin-tx-verifier?tab=readme-ov-file)

