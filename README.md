BioCompiler


BioCompiler is a Rust library for compiling, signing, and verifying genetic sequences while enforcing strict biosafety checks and cryptographic validation.

🚀 Features

Strict DNA validation – only accepts A, C, G, T bases.

Biosafety scanning – detects forbidden sequences and their reverse complements using Aho-Corasick.

Digital signatures – Ed25519 ensures sequence integrity and authenticity.

Time-based verification – signature validity is checked with timestamps and configurable tolerance.

Memory safety – ValidatedDna uses zeroize to erase sensitive data on drop.

Testable design – Clock trait allows deterministic unit testing.

🚀 Next Steps & Roadmap
While this is a functional, the vision for BioCompiler involves bridging the gap between high-level logic and viable synthetic biology. Future iterations will focus on:

1. Biological Constraints & Validation
GC-Content Analysis: Implement automated checks to ensure sequences stay within synthesizable GC-content ranges (typically 40-60%).

Secondary Structure Prediction: Detect and warn against unintended "hairpins" or repeats that could interfere with DNA synthesis or folding.

Codon Optimization: Add support for organism-specific codon usage tables (e.g., optimizing for E. coli vs. Yeast).

2. Industry Standards Integration
SBOL Support: Export generated designs to the Synthetic Biology Open Language (SBOL) standard for interoperability with professional bio-design tools.

Standard BioBricks Library: Map high-level functions (if, while) to characterized genetic parts (Promoters, Ribosome Binding Sites, Terminators).

3. Simulation & Visualization
Virtual Execution: Create a lightweight simulator to predict how the generated DNA sequence would behave in a cellular environment.

Visual Circuit Mapping: Automatically generate diagrams representing the genetic circuit described by the code.
