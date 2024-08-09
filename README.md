# GRandLine

This repository contains the reference implementation for the **GRandLine Distributed Randomness Beacon Protocol**.

**WARNING:** This is an academic proof-of-concept prototype, and in particular has not beed audited yet - please use it at your own risk.

## Quick Start

GRandLine is written in Rust, but all our benchmarking scripts are written in Python. To deploy and benchmark on your local machine, clone the repository with: 

`git clone https://github.com/DimitrisPapac/GRandLine.git`

Switch to the project's root directory and run:

`python3 scripts/local_run.py n t`

where `n` is the number of nodes participating in the randomness generation, and `t` is the time (in seconds) for which you would like the protocol to run.

## License

Licensed under the Apache License. See [LICENSE](/LICENSE).

## Authors

Dimitrios Papachristoudis, Cryptography Researcher.

Simon Ochsenreither, Software Developer.
