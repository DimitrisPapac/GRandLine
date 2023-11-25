use ark_ec::PairingEngine;
use optrand_pvss::{ComGroup, nizk::scheme::NIZKProof};
use optrand_pvss::nizk::dleq::DLEQProof;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum BroadcastMessage<E: PairingEngine> {
    Sigma(u128, usize, (ComGroup<E>, E::Fqk), <DLEQProof<ComGroup<E>, ComGroup<E>> as NIZKProof>::Proof),
    // Ready(Vec<u8>),
}