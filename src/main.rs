use std::sync::atomic::AtomicU64;

use clap::Parser;
use iroh_base::{PublicKey, SecretKey};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

#[derive(Debug, Clone, clap::Parser)]
struct CliArgs {
    /// The needle prefix for the public key to search a secret key for.
    needle: String,
    /// The number of threads to use for search.
    #[clap(long, default_value_t = 1)]
    threads: u64,
    /// Whether to keep searching even after the first find.
    #[clap(long, default_value_t = false)]
    keep_going: bool,
}

fn main() {
    let args = CliArgs::parse();

    let (hex_prefix, half_byte) = args.needle.split_at(args.needle.len() / 2 * 2);
    let prefix = hex::decode(hex_prefix).unwrap();
    let last_byte = half_byte
        .chars()
        .next()
        .map(|first| hex::decode(format!("{first}0")).unwrap()[0]);

    let iterations = AtomicU64::new(0);

    std::thread::scope(|scope| {
        for _ in 0..args.threads {
            scope.spawn(|| run_search(&args, &prefix, last_byte, &iterations));
        }
    });
}

fn run_search(args: &CliArgs, prefix: &[u8], last_byte: Option<u8>, iterations: &AtomicU64) -> ! {
    let mut rng = ChaCha8Rng::from_rng(&mut rand::rng());
    loop {
        let prev = iterations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if prev != 0 && prev % 10_000 == 0 {
            println!("{prev}\t iterations");
        }
        let secret_key = generate(&mut rng);
        let public_key = secret_key.public();
        if found_needle(&public_key, &prefix, last_byte) {
            println!(
                "found {public_key} (secret key: {})",
                hex::encode(secret_key.to_bytes())
            );
            if !args.keep_going {
                std::process::exit(0);
            }
        }
    }
}

fn generate(rng: &mut impl Rng) -> SecretKey {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    SecretKey::from_bytes(&bytes)
}

fn found_needle(public_key: &PublicKey, prefix: &[u8], last_byte: Option<u8>) -> bool {
    if !public_key.starts_with(&prefix) {
        return false;
    }
    if let Some(last_byte) = last_byte {
        let pk_byte = public_key[prefix.len()];
        return (pk_byte & 0b1111_0000) == last_byte;
    }
    true
}
