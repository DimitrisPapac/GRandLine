use bytes::Bytes;
use rand::{rngs::ThreadRng, thread_rng};
use sha3::{
    digest::{ExtendableOutput, XofReader, Update},
    Shake256,
};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    ops::{Mul, Neg},
};
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::{
    Commitment,
    message::BroadcastMessage,
    network::SimpleSender,
};

use optrand_pvss::{
    ComGroup,
    EncGroup,
    GT,
    modified_scrape::{
        config::Config,
        poly::lagrange_interpolation_gt,
    },
    nizk::{
        dleq::{
            DLEQProof,
            srs::SRS as DLEQSRS,
        },
        scheme::NIZKProof,
        utils::hash::hash_to_group,
    },
};

use ark_ec::{AffineCurve, ProjectiveCurve, PairingEngine};
use ark_ff::One;
use ark_serialize::CanonicalSerialize;


//#[cfg(test)]
//#[path = "tests/core_tests.rs"]
//pub mod core_tests;

const PERSONA: &[u8] = b"OnePiece";
const LAMBDA: usize = 256;   // main security parameter

pub struct Core<E: PairingEngine> {
    id: usize,
    nodes: Vec<SocketAddr>,
    sender: SimpleSender,
    rx: Receiver<BroadcastMessage<E>>,
    num_participants: usize,
    num_faults: usize,
    tx_term: Sender<u8>,
    rx_term: Receiver<u8>,
    config: Config<E>,
    pks: Vec<ComGroup<E>>,
    sk: EncGroup<E>,
    cm: Commitment<E>,
    qual: HashSet<usize>,
    current_epoch: u128,
    epoch_generator: ComGroup<E>,
    sigma_map: HashMap<u128, HashMap<usize, (ComGroup<E>, GT<E>)>>,   // {epoch -> {id -> sigma_id}}
    rng: &'static mut ThreadRng,   // gave this a static lifetime
}

impl<E: PairingEngine> Core<E> {
    pub fn spawn(
        id: usize,
        nodes: Vec<SocketAddr>,
        sender: SimpleSender,
        rx: Receiver<BroadcastMessage<E>>,
        num_participants: usize,
        num_faults: usize,
        input: (Config<E>, Vec<ComGroup<E>>, Vec<EncGroup<E>>, Vec<Commitment<E>>, HashSet<usize>),
    ) {
        println!("{} spawning Core", id);

        // Set initial values for epoch counter, epoch generator, and sigma_map
        let mut current_epoch = 0_u128;
        let mut epoch_generator = hash_to_group::<ComGroup<E>>(PERSONA, &current_epoch.to_le_bytes()).unwrap().into_affine();
        let mut sigma_map = HashMap::new();

        // Channel used for terminating the core.
        let (tx_term, rx_term) = channel(1);

        tokio::spawn(async move {
            Self {
                id,
                nodes,
                sender,
                rx,
                num_participants,
                num_faults,
                tx_term,
                rx_term,
                config: input.0,
                pks: input.1,
                sk: input.2[id],
                cm: input.3[id],
                qual: input.4,
                sigma_map,
                current_epoch,
                epoch_generator,
                rng: &mut thread_rng(),
            }
            .run()
            .await;
        });
    }

    async fn handle_sigma(
        &mut self,
        sigma_tup: (u128, usize, (ComGroup<E>, GT<E>), <DLEQProof<ComGroup<E>, ComGroup<E>> as NIZKProof>::Proof)
    ) {
        let (epoch, orig_id, sigma, pi) = sigma_tup;

        if epoch >= self.current_epoch {   // if message is not from a previous epoch
            if  self.qual.contains(&orig_id) {   // if message sender is qualified
                let stmnt = (sigma.0, self.cm.part1);

                let srs = DLEQSRS::<ComGroup<E>, ComGroup<E>> {
                    g_public_key: self.epoch_generator,
                    h_public_key: self.config.srs.g2,
                };
                
                let dleq = DLEQProof::from_srs(srs).unwrap();

                if dleq.verify(&stmnt, &pi).is_ok() {                      
                    let pairs = [
                        (self.cm.part2.neg().into(), self.epoch_generator.into()),
                        (self.config.srs.g1.neg().into(), sigma.0.into()),
                    ];

                    let prod = <E as PairingEngine>::product_of_pairings(pairs.iter());

                    if (sigma.1).mul(prod).is_one() {
                        let inner = self.sigma_map.get_mut(&epoch);
                        
                        if inner.is_some() {   // if epoch already exists 
                            inner.unwrap().insert(orig_id, sigma);
                        } else {   // no entry for this epoch
                            let mut mp = HashMap::<usize, (ComGroup<E>, GT<E>)>::new();
                            mp.insert(orig_id, sigma);
                            self.sigma_map.insert(epoch, mp);
                        }
                        
                        // Check if we can generate the beacon value for the current epoch
                        if let Some(current_epoch_sigmas) = self.sigma_map.get(&self.current_epoch) {
                            // If sufficient reconstruction points have been gathered for the current epoch
                            if current_epoch_sigmas.len() >= self.config.degree + 1 {
                                // Reconstruct sigma := e(g_r, SK)
                                let mut points = Vec::new();
                                let mut evals = Vec::new();

                                let inner = self.sigma_map.get(&self.current_epoch).unwrap();

                                for (&id, (_, e)) in inner {               
                                    points.push(id as u64);             
                                    evals.push(*e);
                                }

                                let sigma = lagrange_interpolation_gt::<E>(&evals, &points, self.config.degree as u64).unwrap();
                                               
                                let mut hasher = Shake256::default();

                                let mut sigma_bytes = Vec::new();
                                sigma.serialize(&mut sigma_bytes);

                                hasher.update(&sigma_bytes[..]);

                                let mut reader = hasher.finalize_xof();

                                let mut beacon_value = [0_u8; LAMBDA >> 3];

                                XofReader::read(&mut reader, &mut beacon_value);

                                // Print beacon value
                                println!("Node {} beacon Value for epoch {}: {:?}\n\n", self.id, self.current_epoch, beacon_value);

                                // Erase entry for previous epoch from sigma_map
                                self.sigma_map.remove(&self.current_epoch);

                                // Increment epoch counter
                                self.current_epoch += 1;

                                // Compute new epoch generator
                                self.epoch_generator = hash_to_group::<ComGroup<E>>(PERSONA, &self.current_epoch.to_le_bytes()).unwrap().into_affine();

                                // Beacon epoch phase computations
                                let (sigma, pi) = self.compute_sigma();

                                // Broadcast to all participants
                                let msg = BroadcastMessage::SigmaMessage((self.current_epoch, self.id, sigma, pi));
                                self.broadcast(msg).await;
                            }
                        } else {   // will likely never need to be executed
                            self.sigma_map.insert(self.current_epoch, HashMap::<usize, (ComGroup<E>, GT<E>)>::new());
                        }
                    }
                }
            }
        }
    }

    /// Broadcast a given message to every node in the network.
    async fn broadcast(&mut self, msg: BroadcastMessage<E>) {
        let bytes = Bytes::from(bincode::serialize(&msg).unwrap());
        self.sender.broadcast(self.nodes.clone(), bytes).await;
    }

    fn compute_sigma(&self) -> ((ComGroup<E>, GT<E>), <DLEQProof<ComGroup<E>, ComGroup<E>> as NIZKProof>::Proof) {
        // Fetch node's random scalar used for its commitment.
        let a_i = self.cm.a_i;

        let sigma = (
            self.epoch_generator.mul(a_i).into_affine(),
            <E as PairingEngine>::pairing::<EncGroup<E>, ComGroup<E>>(self.sk.into(), self.epoch_generator.into()),
        );

        let srs = DLEQSRS::<ComGroup<E>, ComGroup<E>> {
            g_public_key: self.epoch_generator,
            h_public_key: self.config.srs.g2,
        };

        let dleq = DLEQProof { srs };

        let pi = dleq.prove(self.rng, &a_i).unwrap();

        (sigma, pi)
    }

    pub async fn run(&mut self) {
        // Compute initial sigma and DLEQ proof
        let (sigma, pi) = self.compute_sigma();

        // Broadcast to all participants
        let msg = BroadcastMessage::SigmaMessage((self.current_epoch, self.id, sigma, pi));
        self.broadcast(msg).await;

        // Listen to incoming messages and process them. Note: self.rx is the channel where we can
        // retrieve data from the message receiver.
        loop {
            tokio::select! {
                Some(message) = self.rx.recv() => match message {
                    BroadcastMessage::SigmaMessage(sigma_tup) => self.handle_sigma(sigma_tup).await,
                    //BroadcastMessage::Ready(v) => self.handle_ready(v).await,
                },
                Some(_) = self.rx_term.recv() => {
                    println!("Node {} terminating..", self.id);
                    return;
                }
            };
        }
    }
}
