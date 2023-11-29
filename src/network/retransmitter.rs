use std::net::SocketAddr;

use ark_ec::PairingEngine;
use futures::{stream::FuturesUnordered, StreamExt};
use log::trace;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration};

use crate::message::SigmaMessage;

pub struct SimpleRetransmitter<E: PairingEngine> {
    rx: Receiver<(SigmaMessage<E>, SocketAddr)>,
    tx: Sender<SigmaMessage<E>>,
}

impl<E: PairingEngine> SimpleRetransmitter<E> {
    pub fn new(
        rx: Receiver<(SigmaMessage<E>, SocketAddr)>,
        tx: Sender<SigmaMessage<E>>,
    ) -> Self {
        Self { rx, tx }
    }

    pub async fn run(&mut self) {
        let mut pending = FuturesUnordered::new();
        loop {
            tokio::select! {
                Some((mes, _)) = self.rx.recv() => {
                    pending.push(Self::delay(mes));
                }
                Some(mes) = pending.next() => self.tx.send(mes).await.unwrap(),
            }
        }
    }

    async fn delay(message: SigmaMessage<E>) -> SigmaMessage<E> {
        trace!(
            "Delaying message (id: {}, epoch: [{}]",
            message.id,
            message.epoch
        );
        sleep(Duration::from_millis(100)).await;
        message
    }
}
