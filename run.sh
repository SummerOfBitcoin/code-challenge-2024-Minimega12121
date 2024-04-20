# Update this file to run your own code
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

chmod +x ./target/release/code-challenge-2024-lla-dane
./target/release/code-challenge-2024-lla-dane

cargo build --release

cargo run