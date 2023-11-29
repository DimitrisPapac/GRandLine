use std::net::SocketAddr;

use ark_ec::PairingEngine;
use ark_serialize::CanonicalDeserialize;
use futures::StreamExt;
use log::{trace, warn};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc::Sender,
};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::message::SigmaMessage;

//#[cfg(test)]
//#[path = "../tests/receiver_tests.rs"]
//pub mod receiver_tests;

// For each incoming request we spawn a new worker responsible to receive messages and forward them.
pub struct SimpleReceiver<E: PairingEngine> {
    /// Address to listen to.
    address: SocketAddr,

    /// Channel to send received messages to.
    deliver: Sender<SigmaMessage<E>>,
}

impl<E: PairingEngine> SimpleReceiver<E> {
    pub fn new(address: SocketAddr, deliver: Sender<SigmaMessage<E>>) -> Self {
        Self { address, deliver }
    }

    pub async fn run(&self) {
        // Bind to given ip address
        let listener = TcpListener::bind(&self.address)
            .await
            .expect("Failed to bind TCP port");

        // Wait for incoming connections. If someone wants to connect spawn a new worker who is
        // responsible for handling the connection.
        loop {
            // Accept incoming connection and store it as socket.
            let (socket, addr) = match listener.accept().await {
                Ok(value) => value,
                Err(_e) => {
                    continue;
                }
            };
            trace!("Incoming connection from {:?}", addr);
            // Spawn worker with socket as argument and channel, where he can put his data into.
            Self::spawn_worker(socket, self.deliver.clone()).await;
        }
    }

    async fn spawn_worker(socket: TcpStream, deliver: Sender<SigmaMessage<E>>) {
        trace!("Spawning worker");
        tokio::spawn(async move {
            let transport = Framed::new(socket, LengthDelimitedCodec::new());
            let (_, mut reader) = transport.split();
            while let Some(frame) = reader.next().await {
                match frame {
                    Ok(message) => {
                        // Deserialize network message.
                        let mes = SigmaMessage::deserialize(&*message).unwrap();
                        trace!("Received message from {}", mes.id);
                        // Put message into channel, such that it can be retreived with the receiving
                        // end of the channel.
                        deliver.send(mes).await.unwrap();
                    }
                    Err(e) => {
                        warn!("Error receiving data {}", e);
                        return;
                    }
                }
            }
        });
    }
}
