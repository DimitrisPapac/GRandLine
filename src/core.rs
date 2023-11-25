use std::collections::HashSet;
use std::{collections::HashMap, net::SocketAddr};

use bytes::Bytes;
use optrand_pvss::nizk::dleq::DLEQProof;
use optrand_pvss::nizk::scheme::NIZKProof;
use optrand_pvss::nizk::utils::hash::hash_to_group;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::Commitment;
use crate::{message::BroadcastMessage, network::SimpleSender};

use optrand_pvss::{ComGroup, EncGroup};

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine, G2Projective};
use ark_ec::{AffineCurve, ProjectiveCurve, PairingEngine};
use ark_ff::{PrimeField, UniformRand, Zero};
use rand::thread_rng;

use ark_std::collections::BTreeMap;
use optrand_pvss::modified_scrape::pvss::PVSSCore;
use optrand_pvss::modified_scrape::share::PVSSAggregatedShare;
use optrand_pvss::modified_scrape::decryption::DecryptedShare;
use optrand_pvss::modified_scrape::node::Node;
use optrand_pvss::modified_scrape::participant::Participant;
use optrand_pvss::modified_scrape::dealer::Dealer;
use optrand_pvss::generate_production_keypair;
use optrand_pvss::signature::schnorr::SchnorrSignature;
use optrand_pvss::modified_scrape::config::Config;
use optrand_pvss::signature::scheme::SignatureScheme;
use optrand_pvss::modified_scrape::srs::SRS;
use optrand_pvss::signature::schnorr::srs::SRS as SCHSRS;
use optrand_pvss::nizk::dleq::srs::SRS as DLEQSRS;


//#[cfg(test)]
//#[path = "tests/core_tests.rs"]
//pub mod core_tests;

const PERSONA: &[u8] = b"OnePiece";

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
    // current_epoch and sigma_map are accessed both for reading and writing
    current_epoch: u128,
    epoch_generator: ComGroup<E>,
    sigma_map: HashMap<u128, HashMap<usize, (ComGroup<E>, EncGroup<E>)>>,   // {epoch -> {id -> sigma_id}}
    // ready_map: HashMap<Vec<u8>, usize>,
    // ready: bool,
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

        // Compute initial
        let mut current_epoch = 0_u128;
        let mut epoch_generator = hash_to_group::<ComGroup<E>>(PERSONA, &current_epoch.to_le_bytes()).unwrap().into_affine();

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
                // input: input.clone(),
                sigma_map: HashMap::new(),
                current_epoch,
                epoch_generator,
                // ready_map: HashMap::new(),
                // ready: false,
            }
            .run()
            .await;
        });
    }

    async fn handle_sigma(&mut self, v: Vec<u8>) {
        /*
        println!(
            "Node {} received value {:?}",
            self.id,
            std::str::from_utf8(v.as_slice()).unwrap().to_string()
        );
        */

	

        // let m = BroadcastMessage::Echo(v);
        // self.broadcast(m).await;
    }

    /// Broadcast a given message to every node in the network.
    async fn broadcast(&mut self, m: BroadcastMessage<E>) {
        let bytes = Bytes::from(bincode::serialize(&m).unwrap());
        self.sender.broadcast(self.nodes.clone(), bytes).await;
    }

    pub async fn run(&mut self) {
        // If we are leader multicast value
        // if self.id == self.leader {
        //     println!("{} is leader!", self.id);
        //     let m = BroadcastMessage::Commit(self.input.to_vec());
        //     self.broadcast(m).await;
        // }

        

        // let mut current_epoch: u128 = 0;

        // let mut g_r: ComGroup<E>;   // current epoch generator

        // Node's individual rng
        let rng = &mut thread_rng();

        // Fetch node's random scalar used for its commitment.
        let a_i = self.cm.a_i;

        // Compute epoch generator
        // g_r = hash_to_group::<ComGroup<E>>(PERSONA, &self.current_epoch.to_le_bytes()).unwrap().into_affine();

        let sigma = (
            g_r.mul(a_i).into_affine(),
            <E as PairingEngine>::pairing::<EncGroup<E>, ComGroup<E>>(self.sk.into(), g_r.into()),
        );

        let srs = DLEQSRS::<ComGroup<E>, ComGroup<E>>{
            g_public_key: g_r,
            h_public_key: self.config.srs.g2,
        };

        let dleq = DLEQProof { srs };

        let pi_i = dleq.prove(rng, &a_i).unwrap();

        // Listen to incoming messages and process them. Note: self.rx is the channel where we can
        // retrieve data from the message receiver.
        loop {
            tokio::select! {
                Some(message) = self.rx.recv() => match message {
                    BroadcastMessage::Sigma(sigma) => self.handle_sigma(sigma).await,
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