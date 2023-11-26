use ark_ec::PairingEngine;
use optrand_pvss::{ComGroup, nizk::scheme::NIZKProof};
use optrand_pvss::nizk::dleq::DLEQProof;
//use serde::{Deserialize, Serialize};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

// #[derive(Serialize, Deserialize, Debug)]
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
pub enum BroadcastMessage<E: PairingEngine> {
    SigmaMessage((u128, usize, (ComGroup<E>, GT<E>), <DLEQProof<ComGroup<E>, ComGroup<E>> as NIZKProof>::Proof)),
    // Ready(Vec<u8>),
}
