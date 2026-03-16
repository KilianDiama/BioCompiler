use aho_corasick::{AhoCorasick, MatchKind};
use arrayvec::ArrayVec;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const SIG_SIZE: usize = 64;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum BioError {
    #[error("Alphabet ADN invalide : '{0}' non supporté.")]
    InvalidAlphabet(char),
    #[error("Limite de taille dépassée (Séquence max: {0}, Metadata max: {1}).")]
    SizeConstraintViolation(usize, usize),
    #[error("ALERTE BIOSÛRETÉ : Séquence interdite détectée (Pattern ID: {0}).")]
    HazardousSequence(usize),
    #[error("Erreur Cryptographique : {0}")]
    CryptoError(String),
    #[error("Violation de la fenêtre temporelle.")]
    TimestampViolation,
    #[error("Échec de l'initialisation du moteur de scan.")]
    ScannerInitError,
}

/// Abstraction du temps pour permettre des tests unitaires déterministes
pub trait Clock {
    fn now_secs(&self) -> Result<u64, BioError>;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now_secs(&self) -> Result<u64, BioError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| BioError::TimestampViolation)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ValidatedDna(String);

impl Deref for ValidatedDna {
    type Target = str;
    fn deref(&self) -> &Self::Target { &self.0 }
}

pub struct GeneticInstruction<'a> {
    pub promoter: &'a str,
    pub gene: &'a str,
    pub terminator: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedSequence {
    pub dna: ValidatedDna,
    pub signature: [u8; SIG_SIZE],
    pub metadata: String,
    pub timestamp: u64,
    pub version: u32,
}

pub struct BioCompiler<const MAX_SEQ: usize, const MAX_META: usize, C: Clock = SystemClock> {
    ac_scanner: AhoCorasick,
    signing_key: SigningKey,
    metadata: String,
    version: u32,
    clock_tolerance: u64,
    clock: C,
}

impl<const MAX_SEQ: usize, const MAX_META: usize, C: Clock> BioCompiler<MAX_SEQ, MAX_META, C> {
    const PAYLOAD_CAP: usize = MAX_SEQ + MAX_META + 24;

    const RC_TABLE: [u8; 256] = {
        let mut table = [0u8; 256];
        let mut i = 0;
        while i < 256 { table[i] = 0; i += 1; }
        table[b'A' as usize] = b'T'; table[b'T' as usize] = b'A';
        table[b'C' as usize] = b'G'; table[b'G' as usize] = b'C';
        table[b'a' as usize] = b'T'; table[b't' as usize] = b'A';
        table[b'c' as usize] = b'G'; table[b'g' as usize] = b'C';
        table
    };

    pub fn new(
        signing_key: SigningKey,
        restricted_patterns: &[impl AsRef<[u8]>],
        metadata: impl Into<String>,
        version: u32,
        clock_tolerance: u64,
        clock: C,
    ) -> Result<Self, BioError> {
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(restricted_patterns)
            .map_err(|_| BioError::ScannerInitError)?;

        let metadata_str = metadata.into();
        if metadata_str.len() > MAX_META {
            return Err(BioError::SizeConstraintViolation(MAX_SEQ, MAX_META));
        }

        Ok(Self {
            ac_scanner: ac,
            signing_key,
            metadata: metadata_str,
            version,
            clock_tolerance,
            clock,
        })
    }

    pub fn compile_and_sign(&self, instr: GeneticInstruction) -> Result<SignedSequence, BioError> {
        let mut dna_buf = ArrayVec::<u8, MAX_SEQ>::new();

        for part in [instr.promoter, instr.gene, instr.terminator] {
            for &b in part.as_bytes() {
                if b.is_ascii_whitespace() || b.is_ascii_digit() { continue; }
                let base = match b.to_ascii_uppercase() {
                    b @ (b'A' | b'C' | b'G' | b'T') => b,
                    _ => return Err(BioError::InvalidAlphabet(b as char)),
                };
                dna_buf.try_push(base).map_err(|_| BioError::SizeConstraintViolation(MAX_SEQ, MAX_META))?;
            }
        }

        self.run_biosafety_scan(&dna_buf)?;
        let now = self.clock.now_secs()?;

        let payload = self.build_canonical_payload(&dna_buf, now, self.version, self.metadata.as_bytes())?;
        let signature = self.signing_key.sign(&payload);

        // Suppression du unsafe : conversion sûre via ArrayVec -> Vec -> String (Alphabet déjà validé)
        let dna_string = String::from_utf8(dna_buf.to_vec())
            .map_err(|e| BioError::CryptoError(e.to_string()))?;

        Ok(SignedSequence {
            dna: ValidatedDna(dna_string),
            signature: signature.to_bytes(),
            metadata: self.metadata.clone(),
            timestamp: now,
            version: self.version,
        })
    }

    fn run_biosafety_scan(&self, sequence: &[u8]) -> Result<(), BioError> {
        if let Some(m) = self.ac_scanner.find(sequence) {
            return Err(BioError::HazardousSequence(m.pattern().as_usize()));
        }

        let mut rc_buf = ArrayVec::<u8, MAX_SEQ>::new();
        for &b in sequence.iter().rev() {
            rc_buf.push(Self::RC_TABLE[b as usize]);
        }

        if let Some(m) = self.ac_scanner.find(&rc_buf) {
            return Err(BioError::HazardousSequence(m.pattern().as_usize()));
        }
        Ok(())
    }

    fn build_canonical_payload(&self, dna: &[u8], ts: u64, ver: u32, meta: &[u8]) -> Result<ArrayVec<u8, { Self::PAYLOAD_CAP }>, BioError> {
        let mut buf = ArrayVec::new();
        let mut write = |data: &[u8]| buf.try_extend_from_slice(data).map_err(|_| BioError::SizeConstraintViolation(MAX_SEQ, MAX_META));

        write(&(dna.len() as u32).to_le_bytes())?;
        write(dna)?;
        write(&ts.to_le_bytes())?;
        write(&ver.to_le_bytes())?;
        write(&(meta.len() as u32).to_le_bytes())?;
        write(meta)?;
        Ok(buf)
    }

    pub fn verify(&self, signed: &SignedSequence, pk: &VerifyingKey, max_age_secs: u64) -> Result<(), BioError> {
        let payload = self.build_canonical_payload(signed.dna.as_bytes(), signed.timestamp, signed.version, signed.metadata.as_bytes())?;
        let sig = Signature::from_bytes(&signed.signature).map_err(|e| BioError::CryptoError(e.to_string()))?;

        pk.verify(&payload, &sig).map_err(|e| BioError::CryptoError(e.to_string()))?;

        let now = self.clock.now_secs()?;
        if now.saturating_sub(signed.timestamp) > max_age_secs || signed.timestamp > now + self.clock_tolerance {
            return Err(BioError::TimestampViolation);
        }
        Ok(())
    }
}
