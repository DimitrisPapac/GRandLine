use rand::thread_rng;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    ops::{Mul, Neg},
};
use tokio::sync::mpsc::Receiver;

use crate::{message::SigmaMessage, network::SimpleSender, Commitment, Input};

use optrand_pvss::{
    modified_scrape::{config::Config, poly::lagrange_interpolation_gt},
    nizk::{
        dleq::{srs::SRS as DLEQSRS, DLEQProof},
        scheme::NIZKProof,
        utils::hash::hash_to_group,
    },
    ComGroup, EncGroup, GT,
};

use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::One;
use ark_serialize::CanonicalSerialize;

//#[cfg(test)]
//#[path = "tests/core_tests.rs"]
//pub mod core_tests;

const PERSONA: &[u8] = b"OnePiece";
const LAMBDA: usize = 256; // main security parameter

// TODO: I don't know if that name makes sense.
struct Proof<E: PairingEngine> {
    sigma: (ComGroup<E>, GT<E>),
    pi: <DLEQProof<ComGroup<E>, ComGroup<E>> as NIZKProof>::Proof,
}

pub struct Core<E: PairingEngine> {
    id: usize,
    nodes: Vec<SocketAddr>,
    sender: SimpleSender,
    rx: Receiver<SigmaMessage<E>>,
    _num_participants: usize,
    _num_faults: usize,
    config: Config<E>,
    _pks: Vec<ComGroup<E>>,
    sk: EncGroup<E>,
    cm: Commitment<E>,
    qual: HashSet<usize>,
    current_epoch: u64,
    epoch_generator: ComGroup<E>,
    sigma_map: HashMap<u64, HashMap<usize, (ComGroup<E>, GT<E>)>>, // {epoch -> {id -> sigma_id}}
}

impl<E: PairingEngine> Core<E> {
    pub fn spawn(
        id: usize,
        nodes: Vec<SocketAddr>,
        sender: SimpleSender,
        rx: Receiver<SigmaMessage<E>>,
        num_participants: usize,
        num_faults: usize,
        input: Input<E>,
    ) {
        println!("{} spawning Core", id);

        // Set initial values for epoch counter, epoch generator, and sigma_map
        let epoch_generator = hash_to_group::<ComGroup<E>>(PERSONA, &0_u128.to_le_bytes())
            .unwrap()
            .into_affine();

        tokio::spawn(async move {
            Self {
                id,
                nodes,
                sender,
                rx,
                _num_participants: num_participants,
                _num_faults: num_faults,
                config: input.config,
                _pks: input.pks,
                sk: input.sks[id],
                cm: input.commitments[id].clone(),
                qual: input.qual,
                sigma_map: HashMap::new(),
                current_epoch: 0,
                epoch_generator,
            }
            .run()
            .await;
        });
    }

    // TODO: this function is way too big and has too many nested ifs.
    async fn handle_sigma(&mut self, message: SigmaMessage<E>) {
        // let (epoch, orig_id, sigma, pi) = sigma_tup;

        // Return if we receive a message for a previous epoch.
        if message.epoch < self.current_epoch {
            return;
        }

        // If the sender is not qualified return.
        if !self.qual.contains(&message.id) {
            return;
        }

        let stmnt = (message.sigma.0, self.cm.part1);
        let srs = DLEQSRS::<ComGroup<E>, ComGroup<E>> {
            g_public_key: self.epoch_generator,
            h_public_key: self.config.srs.g2,
        };
        let dleq = DLEQProof::from_srs(srs).unwrap();

        // If the proof is invalid return.
        if dleq.verify(&stmnt, &message.pi).is_err() {
            println!("{} got invalid proof from {}", self.id, message.id);
            return;
        }

        let pairs = [
            (self.cm.part2.neg().into(), self.epoch_generator.into()),
            (self.config.srs.g1.neg().into(), message.sigma.0.into()),
        ];

        let prod = <E as PairingEngine>::product_of_pairings(pairs.iter());

        if (message.sigma.1).mul(prod).is_one() {
            let inner = self.sigma_map.get_mut(&message.epoch);

            if inner.is_some() {
                // if epoch already exists
                inner.unwrap().insert(message.id, message.sigma);
            } else {
                // no entry for this epoch
                let mut mp = HashMap::<usize, (ComGroup<E>, GT<E>)>::new();
                mp.insert(message.id, message.sigma);
                self.sigma_map.insert(message.epoch, mp);
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

                    let sigma =
                        lagrange_interpolation_gt::<E>(&evals, &points, self.config.degree as u64)
                            .unwrap();

                    let mut hasher = Shake256::default();

                    let mut sigma_bytes = Vec::new();
                    // TODO: is this serialization correct? Why do we need to serialize here
                    let _ = sigma.serialize(&mut sigma_bytes);

                    hasher.update(&sigma_bytes[..]);

                    let mut reader = hasher.finalize_xof();

                    let mut beacon_value = [0_u8; LAMBDA >> 3];

                    XofReader::read(&mut reader, &mut beacon_value);

                    // Print beacon value
                    println!(
                        "Node {} beacon Value for epoch {}: {:?}\n\n",
                        self.id, self.current_epoch, beacon_value
                    );

                    // Erase entry for previous epoch from sigma_map
                    self.sigma_map.remove(&self.current_epoch);

                    // Increment epoch counter
                    self.current_epoch += 1;

                    // Compute new epoch generator
                    self.epoch_generator =
                        hash_to_group::<ComGroup<E>>(PERSONA, &self.current_epoch.to_le_bytes())
                            .unwrap()
                            .into_affine();

                    // Beacon epoch phase computations
                    let proof = self.compute_sigma();

                    // Broadcast to all participants
                    let msg = SigmaMessage {
                        epoch: self.current_epoch,
                        id: self.id,
                        sigma: proof.sigma,
                        pi: proof.pi,
                        test_message: format!("Hello from node {}. This is a broadcast", self.id),
                    };
                    self.broadcast(msg).await;
                }
            } else {
                // will likely never need to be executed
                self.sigma_map.insert(
                    self.current_epoch,
                    HashMap::<usize, (ComGroup<E>, GT<E>)>::new(),
                );
            }
        }
    }

    /// Broadcast a given message to every node in the network.
    async fn broadcast(&mut self, msg: SigmaMessage<E>) {
        let mut compressed_bytes = Vec::new();
        msg.serialize(&mut compressed_bytes).unwrap();
        self.sender
            .broadcast(self.nodes.clone(), compressed_bytes.into())
            .await;
        println!("{} broadcasting", self.id);
    }

    fn compute_sigma(&self) -> Proof<E> {
        // Fetch node's random scalar used for its commitment.
        let a_i = self.cm.a_i;

        let sigma = (
            self.epoch_generator.mul(a_i).into_affine(),
            <E as PairingEngine>::pairing::<EncGroup<E>, ComGroup<E>>(
                self.sk.into(),
                self.epoch_generator.into(),
            ),
        );

        let srs = DLEQSRS::<ComGroup<E>, ComGroup<E>> {
            g_public_key: self.epoch_generator,
            h_public_key: self.config.srs.g2,
        };

        let dleq = DLEQProof { srs };

        // TODO: is it ok to create a new rng every time this is run?
        // TODO: unwrap
        let pi = dleq.prove(&mut thread_rng(), &a_i).unwrap();

        Proof { sigma, pi }
    }

    pub async fn run(&mut self) {
        // Compute initial sigma and DLEQ proof
        let proof = self.compute_sigma();

        // Broadcast to all participants
        let msg = SigmaMessage {
            epoch: self.current_epoch,
            id: self.id,
            sigma: proof.sigma,
            pi: proof.pi,
            test_message: format!("Hello from node {}. This is the initial broadcast", self.id),
        };
        self.broadcast(msg).await;

        // Listen to incoming messages and process them. Note: self.rx is the channel where we can
        // retrieve data from the message receiver.
        loop {
            if let Some(message) = self.rx.recv().await {
                println!("{} is receiving from {}. Mes: {}", self.id, message.id, message.test_message);
                self.handle_sigma(message).await;
            };
        }
    }
}
