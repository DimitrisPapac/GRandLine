use std::net::SocketAddr;
use tokio::time::{sleep, Duration};

mod config;
mod core;
mod message;
mod network;
mod node;

#[tokio::main]
async fn main() {
    let num_participants = 4; // temporary value for testing purposes
    let num_faults = (num_participants / 2) - 1; // assume maximum number of faults
    println!("Max faults: {}", num_faults);

    // Create local ip addresses with different ports.
    let addresses = (0..num_participants)
        .map(|i| {
            format!("127.0.0.1:{}", config::IP_START + i)
                .parse::<SocketAddr>()
                .unwrap()
        })
        .collect::<Vec<_>>();

    // Spawn nodes.
    for i in 0..num_participants {
        let addresses = addresses.clone();
        tokio::spawn(async move {
            node::Node::new(i, addresses, num_participants, num_faults).await;
        });
    }

    sleep(Duration::from_millis(5_000)).await;
}
