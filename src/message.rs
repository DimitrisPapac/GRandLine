use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};

use optrand_pvss::{
    nizk::{dleq::DLEQProof, scheme::NIZKProof},
    ComGroup, GT,
};

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct SigmaMessage<E: PairingEngine> {
    pub epoch: u64,
    pub id: usize,
    pub sigma: (ComGroup<E>, GT<E>),
    pub pi: <DLEQProof<ComGroup<E>, ComGroup<E>> as NIZKProof>::Proof,
}
