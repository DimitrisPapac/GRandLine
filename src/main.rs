use ark_ec::{AffineCurve, ProjectiveCurve, PairingEngine};
use ark_ff::{UniformRand, One};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::collections::BTreeMap;

use rand::thread_rng;
use std::marker::PhantomData;
use std::io::Write;
use std::fs::{self, File};
use std::net::SocketAddr;
use std::ops::Neg;
use std::path::Path;
use tokio::time::{sleep, Duration};

use optrand_pvss::{ComGroup, EncGroup, Scalar};
use optrand_pvss::modified_scrape::errors::PVSSError;
use optrand_pvss::modified_scrape::pvss::PVSSCore;
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
use std::collections::HashSet;
use ark_serialize::SerializationError;
use ark_serialize::Read;


mod core;
mod message;
mod network;
mod node;


const IP_START: usize = 9_000;


#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct Commitment<E: PairingEngine> {
    pub id: usize,
    pub a_i: Scalar<E>,
    pub part1: ComGroup<E>,
    pub part2: EncGroup<E>,
}

unsafe impl<E: PairingEngine> Send for Commitment<E> {}

fn generate_setup_files<E: PairingEngine>(
    num_participants: usize,
    degree: usize,
    config_path: &str,
    pks_path: &str,
    sks_path: &str,
    cms_path: &str,
    ips_path: &str,
) {
    let rng = &mut thread_rng();

    let mut ips_file = File::create(ips_path).unwrap();
    for i in 0..num_participants {
        let line = format!("127.0.0.1:{}", IP_START + i);
        writeln!(ips_file, "{}", line);
    }

    // Generate new srs and config
    let srs = SRS::<E>::setup(rng).unwrap();

    // Set global configuration parameters
    let conf = Config {
        srs: srs.clone(),
        degree,
        num_participants,
    };

    let mut conf_bytes = vec![];
    conf.serialize(&mut conf_bytes).unwrap();

    let mut conf_file = fs::File::create(&config_path).unwrap();

    conf_file.write_all(&conf_bytes).unwrap();
    
    let schnorr_srs = SCHSRS::<EncGroup::<E>>::from_generator(conf.srs.g1).unwrap();
    let schnorr_sig = SchnorrSignature { srs: schnorr_srs };

    let mut dealers = vec![];
    let mut nodes = vec![];

    for id in 0..num_participants {
        // Generate key pairs for party
        let dealer_keypair_sig = schnorr_sig.generate_keypair(rng).unwrap();   // (sk, pk)
        let eddsa_keypair = generate_production_keypair();                     // (pk, sk)

        // Create the dealer instance for party
        let dealer: Dealer<E, SchnorrSignature<EncGroup<E>>> = Dealer {
            private_key_sig: dealer_keypair_sig.0,
            private_key_ed: eddsa_keypair.1,
            participant: Participant {
                pairing_type: PhantomData,
                id,
                public_key_sig: dealer_keypair_sig.1,
                public_key_ed: eddsa_keypair.0,
            },
        };

        dealers.push(dealer);
    }

    let participants_vec = (0..num_participants)
        .map(|i| dealers[i].participant.clone())
        .collect::<Vec<_>>();

    let mut participants = BTreeMap::new();
    for (id, party) in (0..num_participants).zip(participants_vec) {
        participants.insert(id, party);
    }
    
    for i in 0..num_participants {
        // Create the node instance for party
        let node = Node::new(
            conf.clone(),
            schnorr_sig.clone(),
            dealers[i].clone(),
            participants.clone(),
        ).unwrap();

        nodes.push(node);
    }

    // Generate a vector of random scalars
    let s = (0..num_participants)
        .map(|_| <E as PairingEngine>::Fr::rand(rng))
        .collect::<Vec<_>>();

    let pvss_core = PVSSCore::<E> {
        encs:  (0..num_participants).map(|i| nodes[i]
                .aggregator
                .participants
                .get(&i)
                .ok_or(PVSSError::<E>::InvalidParticipantId(i))
                .unwrap()
                .public_key_sig
                .mul(s[i]).into_affine()).collect::<Vec<EncGroup<E>>>(),
        comms: (0..num_participants).map(|i| conf.srs.g2.mul(s[i]).into_affine()).collect::<Vec<ComGroup<E>>>(),   // PKs
    };

    // Compute "secret key shares" for all nodes
    let sks = (0..num_participants)
            .map(|i| DecryptedShare::<E>::generate(&pvss_core.encs,
                &nodes[i].dealer.private_key_sig, 
                nodes[i].dealer.participant.id).dec)
            .collect::<Vec<_>>();

    let mut sks_bytes = vec![];
    sks.serialize(&mut sks_bytes).unwrap();

    let mut sks_file = fs::File::create(&sks_path).unwrap();

    sks_file.write_all(&sks_bytes).unwrap();

    // Compute the shared "public key shares"
    let pks = pvss_core.comms.clone();

    let mut pks_bytes = vec![];
    pks.serialize(&mut pks_bytes).unwrap();

    let mut pks_file = fs::File::create(&pks_path).unwrap();

    pks_file.write_all(&pks_bytes).unwrap();

    // Compute commitments vector for each party
    let mut cms = vec![];

    for i in 0..num_participants {
        let a_i = <E as PairingEngine>::Fr::rand(rng);
        
        let cm_i = Commitment::<E> {
            id: i,
            a_i,
            part1: conf.srs.g2.mul(a_i).into_affine(),   // into_repr()
            part2: sks[i] + conf.srs.g1.mul(a_i).neg().into_affine(),   // into_repr()
        };

        cms.push(cm_i);
    }

    let mut cms_bytes = vec![];

    cms.serialize(&mut cms_bytes).unwrap();

    let mut cms_file = fs::File::create(&cms_path).unwrap();

    cms_file.write_all(&cms_bytes).unwrap();
}

fn parse_files<E: PairingEngine>(
    num_participants: usize,
    num_faults: usize,
    config_path: &str,
    pks_path: &str,
    sks_path: &str,
    cms_path: &str,
    ips_path: &str,
) -> (Config<E>, Vec<ComGroup<E>>, Vec<EncGroup<E>>, Vec<Commitment<E>>, HashSet<usize>) {
    // Read config from file
    let config = Config::<E>::deserialize(&*fs::read(&config_path).unwrap()).unwrap();

    // Read SKs from file
    let sks = Vec::<EncGroup<E>>::deserialize(&*fs::read(&sks_path).unwrap()).unwrap();

    // Read PKs from file
    let pks = Vec::<ComGroup<E>>::deserialize(&*fs::read(&pks_path).unwrap()).unwrap();

    let cms = Vec::<Commitment<E>>::deserialize(&*fs::read(&cms_path).unwrap()).unwrap();

    let mut qual = HashSet::new();
    for i in 0..cms.len() {
        let pairs = [
            (config.srs.g1.neg().into(), pks[i].into()),
            (config.srs.g1.into(), cms[i].part1.into()),
            (cms[i].part2.into(), config.srs.g2.into()),
        ];

        let prod = <E as PairingEngine>::product_of_pairings(pairs.iter());

        if prod.is_one() {
            qual.insert(i);
        }
    }

    (config, pks, sks, cms, qual)
}

fn setup<E: PairingEngine>(
    num_participants: usize,
    num_faults: usize,
) -> (Config<E>, Vec<ComGroup<E>>, Vec<EncGroup<E>>, Vec<Commitment<E>>, HashSet<usize>) {
    let config_path = format!("config_{}_{}.txt", num_participants, num_faults);
    let pks_path = format!("pks_{}_{}.txt", num_participants, num_faults);
    let sks_path = format!("sks_{}_{}.txt", num_participants, num_faults);
    let cms_path = format!("cms_{}_{}.txt", num_participants, num_faults);
    let ips_path = format!("ips_{}_{}.txt", num_participants, num_faults);

    // If no config file exists, generate entire setup from scrath
    if !Path::new(config_path.as_str()).exists() {
        generate_setup_files::<E>(num_participants, num_faults, &config_path, &pks_path, &sks_path, &cms_path, &ips_path);
    }
    
    // Parse files and return output tuple to caller:
    // (config, pks, sks, cms, qual)
    parse_files::<E>(num_participants, num_faults, &config_path, &pks_path, &sks_path, &cms_path, &ips_path)
}

#[tokio::main]
async fn main() {
    let num_participants = 4;   // temporary value for testing purposes
    let num_faults = (num_participants >> 1) - 1;   // assume maximum number of faults

    // Create local ip addresses with different ports.
    let addresses = (0..num_participants)
        .map(|i| format!("127.0.0.1:{}", IP_START + i).parse::<SocketAddr>().unwrap())
        .collect::<Vec<_>>();

    // Spawn nodes.
    for i in 0..num_participants {
        let addresses = addresses.clone();
        tokio::spawn(async move {
            node::Node::new(i, addresses,num_participants, num_faults).await;
        });
    }

    sleep(Duration::from_millis(5_000)).await;
}
