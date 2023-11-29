use ark_bls12_381::Bls12_381;
use clap::Parser;
use crate::config::generate_setup_files;

#[derive(Debug, Parser)]
#[clap(author, version, about)]
struct ConfigArgs {
    /// Number of participants
    num_participants: usize,
    /// Number of faults
    num_faults: Option<usize>,
}

mod config;

fn main() {
    let args = ConfigArgs::parse();

    let num_faults = match args.num_faults {
        Some(faults) => faults,
        None => (args.num_participants / 2) - 1,
    };

    generate_setup_files::<Bls12_381>(args.num_participants, num_faults);
}
