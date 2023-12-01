sudo apt-get -y update
sudo apt install -y make
sudo apt install -y build-essential
sudo apt-get install -y git build-utils

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > install-rust.sh
bash install-rust.sh -y
source $HOME/.cargo/env

git clone https://github.com/sochsenreither/grandline.git
cd grandline
git pull

cargo build --bin app --release
