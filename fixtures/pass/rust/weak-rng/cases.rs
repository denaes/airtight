// False positive cases for rust/weak-rng

use rand::Rng;
use rand::SeedableRng;

fn pass_cases() {
    // Case 1: Cryptographically secure OsRng instance
    let mut rng = rand::rngs::OsRng;

    // Case 2: Generating token with OsRng
    let token = rand::rngs::OsRng.gen::<[u8; 32]>();

    // Case 3: Rolling a dice with thread_rng (non-security random)
    let dice = rand::thread_rng().gen_range(1..=6);

    // Case 4: Backoff jitter with thread_rng (non-security random)
    let jitter_ms = rand::thread_rng().gen_range(50..200);

    // Case 5: Insecure generator in commented line
    // let token = rand::thread_rng().gen::<[u8; 32]>();

    // Case 6: Deterministic StdRng seeding
    let mut std_rng = rand::rngs::StdRng::seed_from_u64(42);

    // Case 7: Token generated from StdRng
    let auth_token: u64 = rand::rngs::StdRng::seed_from_u64(1234).gen();

    // Case 8: Shuffling items using random()
    let items = vec![1, 2, 3, 4, 5];
    let shuffle_idx = rand::random::<usize>() % items.len();

    // Case 9: Statistical float sampling
    let sample_val: f64 = rand::random();
}
