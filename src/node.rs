use ark_ec::PairingEngine;
use log::debug;

use std::net::SocketAddr;
use tokio::{
    sync::mpsc::channel,
    time::{sleep, Duration},
};

use crate::{
    config::Input,
    core::Core,
    network::{SimpleReceiver, SimpleRetransmitter, SimpleSender},
};

pub async fn new<E: PairingEngine>(
    id: usize,
    nodes: Vec<SocketAddr>,
    num_participants: usize,
    num_faults: usize,
    input: Input<E>,
) {
    // Create a channel for networking.
    let (tx_rec, rx_rec) = channel(1_000);
    let (tx_send, rx_send) = channel(1_000);
    let (tx_retransmit, rx_retransmit) = channel(1_000);

    let mut addresses = nodes.clone();
    addresses.remove(id);
    let listen_address = format!("0.0.0.0:{}", 9000 + id)
        .parse::<SocketAddr>()
        .unwrap();

    // Create a retransmitter, receiver and sender.
    let mut retransmitter = SimpleRetransmitter::<E>::new(rx_retransmit, tx_send.clone());
    let receiver = SimpleReceiver::new(listen_address, tx_rec);
    let mut sender = SimpleSender::new(rx_send, tx_retransmit, addresses.clone());

    // Run retransmitter, receiver and sender.
    debug!("Setting up network.. Listen address: {}", listen_address);
    tokio::spawn(async move {
        retransmitter.run().await;
    });

    tokio::spawn(async move {
        receiver.run().await;
    });

    tokio::spawn(async move {
        sender.run().await;
    });

    sleep(Duration::from_millis(100)).await;

    Core::spawn(id, tx_send, rx_rec, num_participants, num_faults, input).await;
}
