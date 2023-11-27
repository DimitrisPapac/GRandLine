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

struct Proof<E: PairingEngine> {
    sigma: (ComGroup<E>, GT<E>),
    pi: <DLEQProof<ComGroup<E>, ComGroup<E>> as NIZKProof>::Proof,
}

pub struct Core<E: PairingEngine> {
    id: usize,
    nodes: Vec<SocketAddr>,
    sender: SimpleSender,
    rx: Receiver<SigmaMessage<E>>,
    num_participants: usize,
    _num_faults: usize,
    config: Config<E>,
    _pks: Vec<ComGroup<E>>,
    sk: EncGroup<E>,
    cms: Vec<Commitment<E>>,
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
        println!("{} spawning Core.", id);

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
                num_participants,
                _num_faults: num_faults,
                config: input.config,
                _pks: input.pks,
                sk: input.sks[id],
                cms: input.commitments.clone(),
                sigma_map: HashMap::new(),
                current_epoch: 0,
                epoch_generator,
            }
            .run()
            .await;
        });
    }

    #[async_recursion]
    async fn handle_sigma(&mut self, message: SigmaMessage<E>) {
        // let (epoch, orig_id, sigma, pi) = sigma_tup;

        // Return if we receive a message for a previous epoch.
        if message.epoch < self.current_epoch {
            return;
        }

        // Check if the sender is qualified
        if message.id >= self.num_participants {
            return;
        }

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
            (self.config.srs.g1.neg().into(), message.sigma.0.into()),
        ];

        let prod = <E as PairingEngine>::product_of_pairings(pairs.iter());

        if !(message.sigma.1).mul(prod).is_one() {
            return;
        }

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

        // Check if we have enough reconstruction points.
        match self.sigma_map.get(&self.current_epoch) {
            Some(sigmas) => {
                if sigmas.len() >= self.config.degree + 1 {
                    self.compute_beacon();
                    self.increase_epoch().await;
                }
            }
            None => {
                // TODO: maybe check return value?
                self.sigma_map.insert(
                    self.current_epoch,
                    HashMap::<usize, (ComGroup<E>, GT<E>)>::new(),
                );
            }
        }
    }

    fn compute_beacon(&mut self) {
        let sigmas = self.sigma_map.get(&self.current_epoch).unwrap();

        // Reconstruct sigma := e(g_r, SK)
        let mut points = Vec::new();
        let mut evals = Vec::new();

        for i in 0..(self.num_participants) {
            if sigmas.contains_key(&i) {
                points.push(i as u64);
                evals.push(sigmas[&i].1)
            }
        }

        let sigma =
            lagrange_interpolation_gt::<E>(&evals, &points, self.config.degree as u64).unwrap();

        let mut hasher = Shake256::default();
        let mut sigma_bytes = Vec::new();
        let _ = sigma.serialize(&mut sigma_bytes);
        hasher.update(&sigma_bytes[..]);

        let mut reader = hasher.finalize_xof();

        let mut beacon_value = [0_u8; LAMBDA >> 3];

        XofReader::read(&mut reader, &mut beacon_value);

        // Print beacon value
        println!(
            "Node {}, epoch {}: {:?}",
            self.id, self.current_epoch, beacon_value
        );
    }

    #[async_recursion]
    async fn increase_epoch(&mut self) {
        // Increment epoch counter
        self.current_epoch += 1;

        // Erase entry for previous epoch from sigma_map
        self.sigma_map.remove(&self.current_epoch);

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
        };
        self.broadcast(msg.clone()).await;
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
        // Compute initial sigma and DLEQ proof
        let proof = self.compute_sigma();

        // Broadcast to all participants
        let msg = SigmaMessage {
            epoch: self.current_epoch,
            id: self.id,
            sigma: proof.sigma,
            pi: proof.pi,
        };
        self.broadcast(msg.clone()).await;

        // Listen to incoming messages and process them. Note: self.rx is the channel where we can
        // retrieve data from the message receiver.
        loop {
            if let Some(message) = self.rx.recv().await {
                self.handle_sigma(message).await;
            };
        }
    }
}
