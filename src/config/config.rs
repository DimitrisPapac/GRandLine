use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{One, UniformRand};
use ark_poly::{polynomial::UVPolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError};
use ark_std::collections::BTreeMap;

use rand::thread_rng;
use std::{
    collections::HashSet,
    fs::{self, File},
    io::{self, BufRead, Write},
    marker::PhantomData,
    net::SocketAddr,
    ops::Neg,
    path::Path,
};

use optrand_pvss::{
    generate_production_keypair,
    modified_scrape::{
        config::Config, dealer::Dealer, decryption::DecryptedShare, errors::PVSSError, node::Node,
        participant::Participant, poly::Polynomial as Poly, pvss::PVSSCore, srs::SRS,
    },
    signature::{scheme::SignatureScheme, schnorr::srs::SRS as SCHSRS, schnorr::SchnorrSignature},
    ComGroup, EncGroup, Scalar,
};

#[derive(Debug, Clone)]
pub struct Input<E: PairingEngine> {
    pub config: Config<E>,
    pub pks: Vec<ComGroup<E>>,
    pub sks: Vec<EncGroup<E>>,
    pub commitments: Vec<Commitment<E>>,
    pub qual: HashSet<usize>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct Commitment<E: PairingEngine> {
    pub id: usize,
    pub a_i: Scalar<E>,
    pub part1: ComGroup<E>,
    pub part2: EncGroup<E>,
}

unsafe impl<E: PairingEngine> Send for Commitment<E> {}

#[allow(dead_code)]
pub fn generate_setup_files<E: PairingEngine>(
    num_participants: usize,
    num_faults: usize,
) {
    let cfg_path = format!("configs/{}_{}cfg", num_participants, num_faults);
    let pks_path = format!("configs/{}_{}pks", num_participants, num_faults);
    let sks_path = format!("configs/{}_{}sks", num_participants, num_faults);
    let cms_path = format!("configs/{}_{}cms", num_participants, num_faults);
    let rng = &mut thread_rng();

    // Generate new srs and config
    let srs = SRS::<E>::setup(rng).unwrap();

    // Set global configuration parameters
    let conf = Config {
        srs: srs.clone(),
        degree: num_faults,
        num_participants,
    };

    let mut conf_bytes = vec![];
    conf.serialize(&mut conf_bytes).unwrap();

    let mut conf_file = fs::File::create(&cfg_path).unwrap();

    conf_file.write_all(&conf_bytes).unwrap();

    let schnorr_srs = SCHSRS::<EncGroup<E>>::from_generator(conf.srs.g1).unwrap();
    let schnorr_sig = SchnorrSignature { srs: schnorr_srs };

    let mut dealers = vec![];
    let mut nodes = vec![];

    for id in 0..num_participants {
        // Generate key pairs for party
        let dealer_keypair_sig = schnorr_sig.generate_keypair(rng).unwrap(); // (sk, pk)
        let eddsa_keypair = generate_production_keypair(); // (pk, sk)

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
        )
        .unwrap();

        nodes.push(node);
    }

    // Sample a random polynomial of degree t.
    let f = Poly::<E>::rand(num_faults, rng);

    // Compute polynomial evaluations: f(1), ..., f(n).
    let s = (1..=num_participants)
        .map(|i| f.evaluate(&Scalar::<E>::from(i as u64)))
        .collect::<Vec<_>>();

    let pvss_core = PVSSCore::<E> {
        encs: (0..num_participants)
            .map(|i| {
                nodes[i]
                    .aggregator
                    .participants
                    .get(&i)
                    .ok_or(PVSSError::<E>::InvalidParticipantId(i))
                    .unwrap()
                    .public_key_sig
                    .mul(s[i])
                    .into_affine()
            })
            .collect::<Vec<EncGroup<E>>>(),
        comms: (0..num_participants)
            .map(|i| conf.srs.g2.mul(s[i]).into_affine())
            .collect::<Vec<ComGroup<E>>>(), // PKs
    };

    // Compute "secret key shares" for all nodes
    let sks = (0..num_participants)
        .map(|i| {
            DecryptedShare::<E>::generate(
                &pvss_core.encs,
                &nodes[i].dealer.private_key_sig,
                nodes[i].dealer.participant.id,
            )
            .dec
        })
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
            part1: conf.srs.g2.mul(a_i).into_affine(), // into_repr()
            part2: sks[i] + conf.srs.g1.mul(a_i).neg().into_affine(), // into_repr()
        };

        cms.push(cm_i);
    }

    let mut cms_bytes = vec![];

    cms.serialize(&mut cms_bytes).unwrap();

    let mut cms_file = fs::File::create(&cms_path).unwrap();

    cms_file.write_all(&cms_bytes).unwrap();
}

#[allow(dead_code)]
pub fn parse_files<E: PairingEngine>(num_participants: usize, num_faults: usize) -> Input<E> {
    let cfg_path = format!("configs/{}_{}cfg", num_participants, num_faults);
    let pks_path = format!("configs/{}_{}pks", num_participants, num_faults);
    let sks_path = format!("configs/{}_{}sks", num_participants, num_faults);
    let cms_path = format!("configs/{}_{}cms", num_participants, num_faults);

    // Read config from file
    let config = Config::<E>::deserialize(&*fs::read(&cfg_path).unwrap()).unwrap();

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

    Input {
        config,
        pks,
        sks,
        commitments: cms,
        qual,
    }
}

#[allow(dead_code)]
pub fn parse_ip_file(filename: String) -> Vec<SocketAddr> {
    let mut addresses = Vec::new();

    if let Ok(lines) = read_lines(filename) {
        for line in lines {
            if let Ok(ip) = line {
                addresses.push(ip.parse::<SocketAddr>().unwrap())
            }
        }
    }

    addresses
}

// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
#[allow(dead_code)]
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
