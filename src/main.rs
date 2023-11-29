use std::net::SocketAddr;
use ark_bls12_381::Bls12_381;
use tokio::time::{sleep, Duration};

use crate::config::generate_setup_files;

mod config;
mod core;
mod message;
mod network;
mod node;

#[tokio::main]
async fn main() {
    let num_participants = 4; // temporary value for testing purposes
    let num_faults = (num_participants >> 1) - 1; // assume maximum number of faults
    println!("Max faults: {}", num_faults);

    // Create local ip addresses with different ports.
    let addresses = (0..num_participants)
        .map(|i| {
            format!("127.0.0.1:{}", config::IP_START + i)
                .parse::<SocketAddr>()
                .unwrap()
        })
        .collect::<Vec<_>>();

    // Moved file generation here to have it execute only once.
    let config_path = format!("config_{}_{}.txt", num_participants, num_faults);
    let pks_path = format!("pks_{}_{}.txt", num_participants, num_faults);
    let sks_path = format!("sks_{}_{}.txt", num_participants, num_faults);
    let cms_path = format!("cms_{}_{}.txt", num_participants, num_faults);
    let ips_path = format!("ips_{}_{}.txt", num_participants, num_faults);
    generate_setup_files::<Bls12_381>(num_participants, num_faults, &config_path, &pks_path, &sks_path, &cms_path, &ips_path);
    

    // Spawn nodes.
    for i in 0..num_participants {
        let addresses = addresses.clone();
        tokio::spawn(async move {
            node::Node::new(i, addresses, num_participants, num_faults).await;
        });
    }

    sleep(Duration::from_millis(12_000)).await;
}
