use ark_bls12_381::Bls12_381;
use clap::Parser;
use config::parse_ip_file;
use log::debug;

use crate::config::parse_files;

mod config;
mod core;
mod message;
mod network;
mod node;

#[derive(Debug, Parser)]
#[clap(author, version, about)]
struct AppArgs {
    /// Id of the node
    node_id: usize,
    /// Path to the file containing all IPs
    nodes: String,
    /// Level of logging
    log_level: usize,
}

#[tokio::main]
async fn main() {
    let args = AppArgs::parse();

    // Parse ip file
    let addresses = parse_ip_file(args.nodes);

    let log_level = match args.log_level {
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    // Set up logger
    env_logger::builder()
        .filter_level(log_level)
        .format_target(false)
        .format_timestamp_millis()
        .init();

    debug!("Addresses: {:?}", addresses);

    let num_participants = addresses.len();      // number of participants in the network
    let num_faults = (num_participants / 2) - 1; // assume maximum number of faults (i.e., floor(num_participants/2) - 1)

    let input = parse_files::<Bls12_381>(num_participants, num_faults);

    // Spawn node
    node::new(args.node_id, addresses, num_participants, num_faults, input).await;
}
