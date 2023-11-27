use ark_bls12_381::Bls12_381;

use std::net::SocketAddr;
use tokio::{
    sync::mpsc::channel,
    time::{sleep, Duration},
};

use crate::{
    core::Core,
    network::{MessageReceiver, SimpleSender},
    setup,
};

pub struct Node;

impl Node {
    pub async fn new(id: usize, nodes: Vec<SocketAddr>, num_participants: usize, num_faults: usize) {
        // Create a channel for the message receiver. The receiver receives data from incoming
        // tcp connections and puts this data into the channel. The data is retreives via the rx
        // channel.
        let (tx, rx) = channel(1_000);
        MessageReceiver::spawn(nodes[id], tx);
        let sender = SimpleSender::new();

        // Simulate setup.
        // (config, pks, sks, cms, qual)
        let input = setup::<Bls12_381>(num_participants, num_faults);

        sleep(Duration::from_millis(500)).await;
        
        Core::spawn(id, nodes, sender, rx, num_participants, num_faults, input);
    }
}
