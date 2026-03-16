BioCompiler


BioCompiler is a Rust library for compiling, signing, and verifying genetic sequences while enforcing strict biosafety checks and cryptographic validation.

🚀 Features

Strict DNA validation – only accepts A, C, G, T bases.

Biosafety scanning – detects forbidden sequences and their reverse complements using Aho-Corasick.

Digital signatures – Ed25519 ensures sequence integrity and authenticity.

Time-based verification – signature validity is checked with timestamps and configurable tolerance.

Memory safety – ValidatedDna uses zeroize to erase sensitive data on drop.

Testable design – Clock trait allows deterministic unit testing.
