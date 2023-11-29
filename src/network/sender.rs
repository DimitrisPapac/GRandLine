use std::{collections::HashMap, net::SocketAddr};

use ark_ec::PairingEngine;
use ark_serialize::CanonicalSerialize;
use futures::SinkExt;
use log::{trace, warn};
use tokio::{
    net::TcpStream,
    sync::{
        mpsc::{channel, Receiver, Sender},
        oneshot,
    },
};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::message::SigmaMessage;

pub struct SimpleSender<E: PairingEngine> {
    // Channel for communication between NetworkSender and other threads.
    transmit: Receiver<SigmaMessage<E>>,

    // Channel for communication between NetworkSender and NetworkRetransmitter
    retransmit: Sender<(SigmaMessage<E>, SocketAddr)>,

    // Socket addresses of all nodes (other than the own node).
    addresses: Vec<SocketAddr>,
}

impl<E: PairingEngine> SimpleSender<E> {
    pub fn new(
        transmit: Receiver<SigmaMessage<E>>,
        retransmit: Sender<(SigmaMessage<E>, SocketAddr)>,
        addresses: Vec<SocketAddr>,
    ) -> Self {
        Self {
            transmit,
            retransmit,
            addresses,
        }
    }

    // Keep one TCP connection per peer, handled by a seperate thread. Communication is done via
    // dedicated channels for every worker.
    pub async fn run(&mut self) {
        // Keep track of workers. Maps socket address to sender channel for corresponding worker.
        let mut senders = HashMap::<SocketAddr, Sender<SigmaMessage<E>>>::new();

        while let Some(mes) = self.transmit.recv().await {
            // Always broadcast
            for address in &self.addresses {
                // Spawn is true if there is no sender channel or sending over the channel failed.
                let spawn = match senders.get(&address) {
                    Some(tx) => tx.send(mes.clone()).await.is_err(),
                    None => true,
                };

                if spawn {
                    // Spawn a new worker.
                    let (tx_ok, rx_ok) = oneshot::channel();
                    let tx = Self::spawn_worker(*address, self.retransmit.clone(), tx_ok).await;

                    let mut retransmit = false;

                    match rx_ok.await {
                        Ok(res) => {
                            if res {
                                // Send the new worker the message
                                if let Ok(_) = tx.send(mes.clone()).await {
                                    senders.insert(*address, tx);
                                }
                            } else {
                                warn!("Worker failed to connect to {:?}", address);
                                retransmit = true;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to spawn worker for {:?}: {}", address, e);
                            retransmit = true;
                        }
                    }

                    if retransmit {
                        self.retransmit.send((mes.clone(), address.clone())).await.unwrap();
                    }
                }
            }
        }
    }

    async fn spawn_worker(
        address: SocketAddr,
        retransmit: Sender<(SigmaMessage<E>, SocketAddr)>,
        ok: oneshot::Sender<bool>,
    ) -> Sender<SigmaMessage<E>> {
        // Create channel for communication with SimpleSender.
        let (tx, mut rx): (Sender<SigmaMessage<E>>, Receiver<SigmaMessage<E>>) = channel(1_000);

        tokio::spawn(async move {
            // Connect to address.
            let stream = match TcpStream::connect(address).await {
                Ok(stream) => {
                    trace!("Outgoing connection established with {:?}", address);
                    let _ = ok.send(true);
                    stream
                }
                Err(e) => {
                    warn!("Failed to connect to {:?}: {}", address, e);
                    let _ = ok.send(false);
                    return;
                }
            };

            // Frame the TCP stream
            let mut transport = Framed::new(stream, LengthDelimitedCodec::new());

            while let Some(mes) = rx.recv().await {
                // Serialize the message
                let mut bytes = Vec::new();
                mes.serialize(&mut bytes).unwrap();

                match transport.send(bytes.into()).await {
                    Ok(_) => trace!("Successfully sent message to {:?}", address),
                    Err(e) => {
                        warn!("Failed to send message to {:?}: {}", address, e);
                        retransmit
                            .send((mes.clone(), address.clone()))
                            .await
                            .unwrap();
                        return;
                    }
                }
            }
        });
        tx
    }
}

// pub struct SimpleSender {
//     // Keep track of exisitng connections.
//     connections: HashMap<SocketAddr, Sender<Bytes>>,
// }

// /// Keep alive one TCP connection per peer, each connection is handled by a separate thread.
// impl SimpleSender {
//     pub fn new() -> Self {
//         Self {
//             connections: HashMap::new(),
//         }
//     }

//     fn spawn_connection(address: SocketAddr) -> Sender<Bytes> {
//         trace!("Spawning connection for {:?}", address);
//         let (tx, rx) = channel(1_000);
//         Connection::spawn(address, rx);
//         tx
//     }

//     /// Sends given data to a given address.
//     pub async fn send(&mut self, address: SocketAddr, data: Bytes) {
//         // If we already have a connection established to the given address we use this connection.
//         if let Some(tx) = self.connections.get(&address) {
//             // We put the given data to a channel, where it can be retrieved and send via the
//             // existing tcp connection.
//             if tx.send(data.clone()).await.is_ok() {
//                 return;
//             }
//         }

//         // Otherwise make a new connection and store it in the hashmap.
//         let tx = Self::spawn_connection(address);
//         if tx.send(data).await.is_ok() {
//             self.connections.insert(address, tx);
//         }
//     }

//     /// Sends given data to all given address.
//     pub async fn broadcast(&mut self, addresses: Vec<SocketAddr>, data: Bytes) {
//         for address in addresses {
//             self.send(address, data.clone()).await;
//         }
//     }
// }

// /// A Connection to a single peer.
// struct Connection {
//     /// Destination address.
//     address: SocketAddr,
//     /// Channel to receive data from.
//     receiver: Receiver<Bytes>,
// }

// impl Connection {
//     fn spawn(address: SocketAddr, receiver: Receiver<Bytes>) {
//         tokio::spawn(async move {
//             Self { address, receiver }.run().await;
//         });
//     }

//     /// Main loop for connecting and transmitting.
//     async fn run(&mut self) {
//         // Try to connect to the peer.
//         let (mut writer, _) = match TcpStream::connect(self.address).await {
//             Ok(stream) => Framed::new(stream, LengthDelimitedCodec::new()).split(),
//             Err(_e) => {
//                 warn!("Error trying to connect to {:?}.", self.address);
//                 return;
//             }
//         };

//         // Transmit messages
//         loop {
//             // If there is data in the channel retreive it and send it via the tcp connection.
//             if let Some(data) = self.receiver.recv().await {
//                 trace!("Sending data to {:?}", self.address);
//                 if let Err(_e) = writer.send(data.into()).await {
//                     warn!("Error sending data to {:?}. Closing connection..", self.address);
//                     return;
//                 }
//             }
//         }
//     }
// }
