use ark_ec::PairingEngine;

use std::net::SocketAddr;
use tokio::{
    sync::mpsc::channel,
    time::{sleep, Duration},
};

use crate::{
    config::Input,
    core::Core,
    network::{MessageReceiver, SimpleSender},
};

pub async fn new<E: PairingEngine>(
    id: usize,
    nodes: Vec<SocketAddr>,
    num_participants: usize,
    num_faults: usize,
    input: Input<E>,
) {
    // Create a channel for the message receiver. The receiver receives data from incoming
    // tcp connections and puts this data into the channel. The data is retreives via the rx
    // channel.
    let (tx, rx) = channel(1_000);
    MessageReceiver::spawn(nodes[id], tx);
    let sender = SimpleSender::new();

    sleep(Duration::from_millis(100)).await;

    let mut addresses = nodes.clone();
    addresses.remove(id);
    Core::spawn(
        id,
        addresses,
        sender,
        rx,
        num_participants,
        num_faults,
        input,
    ).await;
}
