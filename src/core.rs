use async_recursion::async_recursion;
use rand::thread_rng;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    ops::{Mul, Neg},
};
use tokio::sync::mpsc::Receiver;

use crate::{config::Commitment, config::Input, message::SigmaMessage, network::SimpleSender};

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

struct Proof<E: PairingEngine> {
    sigma: (ComGroup<E>, GT<E>),
    pi: <DLEQProof<ComGroup<E>, ComGroup<E>> as NIZKProof>::Proof,
}

pub struct Core<E: PairingEngine> {
    id: usize,
    nodes: Vec<SocketAddr>, // Note: does not contain the node's own ip.
    sender: SimpleSender,
    rx: Receiver<SigmaMessage<E>>,
    num_participants: usize,
    num_faults: usize,
    config: Config<E>,
    _pks: Vec<ComGroup<E>>,
    sk: EncGroup<E>,
    cms: Vec<Commitment<E>>,
    current_epoch: u64,
    epoch_generator: ComGroup<E>,
    sigma_map: HashMap<u64, HashMap<usize, (ComGroup<E>, GT<E>)>>, // Need to also store proofs
    // beacons_emitted: u64,
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
        println!("{} spawning Core.", id);

        // Set initial values for epoch counter, epoch generator, and sigma_map
        let current_epoch = 0_u64;
        let epoch_generator = hash_to_group::<ComGroup<E>>(PERSONA, &current_epoch.to_le_bytes())
            .unwrap()
            .into_affine();

        tokio::spawn(async move {
            Self {
                id,
                nodes,
                sender,
                rx,
                num_participants,
                num_faults,
                config: input.config,
                _pks: input.pks,
                sk: input.sks[id],
                cms: input.commitments.clone(),
                sigma_map: HashMap::new(),
                current_epoch,
                epoch_generator,
                // beacons_emitted: 0,
            }
            .run()
            .await;
        });
    }

    #[async_recursion]
    async fn handle_sigma(&mut self, message: SigmaMessage<E>) {
        // Return if we receive a message for a previous epoch.
        if message.epoch < self.current_epoch {
            // println!("Node {}, Epoch {}: Received message with epoch number {}", self.id, self.current_epoch, message.epoch);
            return;
        }

        // Check if the sender is qualified
        if message.id >= self.num_participants {
            println!(
                "Node {}, Epoch {}: Received unqualified message",
                self.id, self.current_epoch
            );
            return;
        }

        // Check if the message is correct wrt my current epoch_generator.
        let stmnt = (message.sigma.0, self.cms[message.id].part1);
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
            (
                self.cms[message.id].part2.neg().into(),
                self.epoch_generator.into(),
            ),
            (
                self.config.srs.g1.neg().into(),
                message.sigma.0.into()
            ),
        ];

        let prod = <E as PairingEngine>::product_of_pairings(pairs.iter());

        if !(message.sigma.1).mul(prod).is_one() {
            return;
        }

        // Put the messages' sigma into the sigma hash map.
        self.store_sigma(&message);

        // Try to construct a beacon value.
        self.try_reconstruction().await;
    }

    /// Stores the sigma of a given message in the sigma hash map.
    fn store_sigma(&mut self, message: &SigmaMessage<E>) {
        match self.sigma_map.get_mut(&message.epoch) {
            Some(sigmas) => {
                sigmas.insert(message.id, message.sigma);
            }
            None => {
                let mut mp = HashMap::<usize, (ComGroup<E>, GT<E>)>::new();
                mp.insert(message.id, message.sigma);
                self.sigma_map.insert(message.epoch, mp);
            }
        }
    }

    /// Checks if we have enough reconstruction points for the current epoch. If yes we can create a
    /// beacon value.
    async fn try_reconstruction(&mut self) {
        // Check if we have enough reconstruction points.
        match self.sigma_map.get(&self.current_epoch) {
            Some(sigmas) => {
                // TODO: FIX
                if sigmas.len() >= self.num_faults + 1 // self.num_participants - self.num_faults
                    //&& sigmas.contains_key(&0)
                {
                    self.compute_beacon();
                    self.increase_epoch().await;
                }
            }
            None => {
                self.sigma_map.insert(
                    self.current_epoch,
                    HashMap::<usize, (ComGroup<E>, GT<E>)>::new(),
                );
            }
        }
    }

    /// Computes a beacon value out of the construction points for the current epoch.
    fn compute_beacon(&mut self) {
        let sigmas = self.sigma_map.get(&self.current_epoch).unwrap();

        // Reconstruct sigma := e(g_r, SK)
        let mut points = Vec::new();
        let mut evals = Vec::new();

        for i in 0..(self.num_participants) {
            if sigmas.contains_key(&i) {
                points.push((i + 1) as u64);   // indices must be in {1, ..., n}
                evals.push(sigmas[&i].1)
            }
        }

        let sigma =
            lagrange_interpolation_gt::<E>(&evals, &points, self.config.degree as u64).unwrap();

        // Generate the beacon value using sigma.
        let mut hasher = Shake256::default();
        let mut sigma_bytes = Vec::new();
        let _ = sigma.serialize(&mut sigma_bytes);
        hasher.update(&sigma_bytes[..]);
        let mut reader = hasher.finalize_xof();
        let mut beacon_value = [0_u8; LAMBDA >> 3];
        XofReader::read(&mut reader, &mut beacon_value);

        // Print beacon value
        println!(
            "Node {}, epoch {}: {:?}. Got keys from: {:?}\n",
            self.id, self.current_epoch, beacon_value, points
        );

        //self.beacons_emitted += 1;
    }

    /// Deletes the no longer needed entries from the sigma hash map, computes a new epoch generator
    /// and broadcasts the new sigma.
    #[async_recursion]
    async fn increase_epoch(&mut self) {
        // Erase entry for previous epoch from sigma_map
        self.sigma_map.remove(&self.current_epoch);

        // Increment epoch counter
        self.current_epoch += 1;

        // Compute new epoch generator
        self.epoch_generator =
            hash_to_group::<ComGroup<E>>(PERSONA, &self.current_epoch.to_le_bytes())
                .unwrap()
                .into_affine();

        self.broadcast_sigma().await;
    }

    /// Compute and broadcast sigma for the current epoch.
    #[async_recursion]
    async fn broadcast_sigma(&mut self) {
        // Beacon epoch phase computations
        let proof = self.compute_sigma();

        // Broadcast to all participants
        let msg = SigmaMessage {
            epoch: self.current_epoch,
            id: self.id,
            sigma: proof.sigma,
            pi: proof.pi,
        };
        self.broadcast(msg).await;
    }

    /// Broadcast a given message to every node in the network.
    #[async_recursion]
    async fn broadcast(&mut self, msg: SigmaMessage<E>) {
        let mut bytes = Vec::new();
        msg.serialize(&mut bytes).unwrap();
        self.sender
            .broadcast(self.nodes.clone(), bytes.into())
            .await;
        self.handle_sigma(msg).await;
    }

    /// Computes and returns a sigma for the current epoch.
    fn compute_sigma(&self) -> Proof<E> {
        // Fetch node's random scalar used for its commitment.
        let a_i = self.cms[self.id].a_i;

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

        let pi = dleq.prove(&mut thread_rng(), &a_i).unwrap();

        Proof { sigma, pi }
    }

    pub async fn run(&mut self) {
        // Broadcast initial sigma.
        self.broadcast_sigma().await;

        // Listen to incoming messages and process them. Note: self.rx is the channel where we can
        // retrieve data from the message receiver.
        loop {
            if let Some(message) = self.rx.recv().await {
                self.handle_sigma(message).await;
            };
        }
    }
}
