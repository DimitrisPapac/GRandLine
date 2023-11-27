use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use optrand_pvss::{
    ComGroup,
    GT,
    nizk::{
        scheme::NIZKProof,
        dleq::DLEQProof,
    },
};
//use serde::{Deserialize, Serialize};

// #[derive(Serialize, Deserialize, Debug)]
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
pub enum BroadcastMessage<E: PairingEngine> {
    SigmaMessage((u128, usize, (ComGroup<E>, GT<E>), <DLEQProof<ComGroup<E>, ComGroup<E>> as NIZKProof>::Proof)),
    // Ready(Vec<u8>),
}
