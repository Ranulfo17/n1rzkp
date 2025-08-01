// Import the necessary definitions from the neutrosophic_numbers module.
mod neutrosophic_numbers;
use neutrosophic_numbers::{NeutrosophicNumber, generate_random_neutrosophic};

/// Simulates the Neutrosophic 1-Round ZKP protocol interaction.
///
/// This function executes the core logic of the ZKP, where Peggy (the prover)
/// attempts to prove knowledge of the secret `x` to Victor (the verifier).
///
/// # Arguments
/// * `g` - The public generator of the group.
/// * `p` - The public neutrosophic modulus (prime).
/// * `b` - The public value `g^x mod p`.
/// * `x` - Peggy's secret key.
///
/// # Returns
/// `true` if the verification succeeds, `false` otherwise.
fn neutrosophic_one_round_zkp_protocol(
    g: &NeutrosophicNumber,
    p: &NeutrosophicNumber,
    b: &NeutrosophicNumber,
    x: &NeutrosophicNumber,
) -> bool {
    let mut rng = rand::thread_rng();

    // Step 1 (Victor): Generate a random secret `y`.
    // In a real scenario, the bit size should match the security level.
    let y = generate_random_neutrosophic(&mut rng, 2048);

    // Step 2 (Victor): Compute the challenge `c = g^y mod p` and send it to Peggy.
    let c = g.pow_mod(&y, p);

    // Step 3 (Peggy): Compute the response `r = c^x mod p` using her secret `x`.
    let r_peggy = c.pow_mod(x, p);

    // Step 4 (Victor): Compute the verification value `r' = b^y mod p` using his secret `y`.
    let r_victor = b.pow_mod(&y, p);

    // Victor checks if Peggy's response matches his verification value.
    r_peggy == r_victor
}

fn main() {
    println!("Starting the Neutrosophic 1-Round ZKP protocol test with 2048-bit numbers...");

    let mut rng = rand::thread_rng();
    let bit_length_params = 2048; // Define the bit size for p, g, x.

    // --- Parameter Setup ---
    // WARNING: This is a simplified setup for algebraic demonstration only.
    // In a real cryptographic system, `p` must be a large prime (or have a specific
    // structure), and `g` must be a generator of the group modulo `p`.
    // The concept of a "neutrosophic prime" is still theoretical and not enforced here.
    let p = generate_random_neutrosophic(&mut rng, bit_length_params);
    let g = generate_random_neutrosophic(&mut rng, bit_length_params);
    let x_secret = generate_random_neutrosophic(&mut rng, bit_length_params);

    // Ensure the generated parameters are "positive" as per the neutrosophic definition.
    if !p.is_positive() || !g.is_positive() {
        eprintln!(
            "Error: The generated public parameters p or g are not positive neutrosophic numbers. Please run again."
        );
        return;
    }

    // Peggy computes her public key `b = g^x mod p`.
    let b = g.pow_mod(&x_secret, &p);

    println!(
        "\nProtocol Parameters ({} bits, truncated for display):",
        bit_length_params
    );
    println!(
        "  g (generator): {}...",
        g.a.to_string().chars().take(50).collect::<String>()
    );
    println!(
        "  p (modulus):   {}...",
        p.a.to_string().chars().take(50).collect::<String>()
    );
    println!(
        "  b (g^x mod p): {}...",
        b.a.to_string().chars().take(50).collect::<String>()
    );
    println!(
        "  x (Peggy's secret): {}...",
        x_secret.a.to_string().chars().take(50).collect::<String>()
    );

    println!("\n--- Test 1: Peggy KNOWS the secret key 'x' ---");
    let result_known_x = neutrosophic_one_round_zkp_protocol(&g, &p, &b, &x_secret);
    if result_known_x {
        println!("Verification SUCCESSFUL! Peggy proved knowledge of 'x' without revealing it.");
    } else {
        println!("Verification FAILED! An error occurred in the protocol logic.");
    }

    println!("\n--- Test 2: Peggy does NOT KNOW the secret key 'x' ---");
    // Generate a fake secret for a dishonest Peggy.
    let x_fake = generate_random_neutrosophic(&mut rng, bit_length_params);
    println!(
        "  Fake x (from Peggy): {}...",
        x_fake.a.to_string().chars().take(50).collect::<String>()
    );
    let result_fake_x = neutrosophic_one_round_zkp_protocol(&g, &p, &b, &x_fake);
    if result_fake_x {
        println!(
            "Verification SUCCEEDED (INCORRECT)! The protocol logic is flawed, as Peggy should not have passed."
        );
    } else {
        println!(
            "Verification FAILED (CORRECT)! Peggy could not prove knowledge of 'x' (because she doesn't know it)."
        );
    }
}

// Unit tests for the neutrosophic number operations.
#[cfg(test)]
mod tests {
    use super::neutrosophic_numbers::*;
    use num_bigint::ToBigInt;

    #[test]
    fn test_neutrosophic_addition() {
        let n1 = NeutrosophicNumber::new(1.to_bigint().unwrap(), 2.to_bigint().unwrap());
        let n2 = NeutrosophicNumber::new(3.to_bigint().unwrap(), 4.to_bigint().unwrap());
        let expected = NeutrosophicNumber::new(4.to_bigint().unwrap(), 6.to_bigint().unwrap());
        assert_eq!(n1 + n2, expected);
    }

    #[test]
    fn test_neutrosophic_multiplication() {
        // Based on I^2 = I
        let n1 = NeutrosophicNumber::new(1.to_bigint().unwrap(), 2.to_bigint().unwrap());
        let n2 = NeutrosophicNumber::new(3.to_bigint().unwrap(), 4.to_bigint().unwrap());
        // (1+2I)*(3+4I) = 1*3 + 1*4I + 2I*3 + 2I*4I = 3 + 4I + 6I + 8I^2 = 3 + 10I + 8I = 3 + 18I
        let expected = NeutrosophicNumber::new(3.to_bigint().unwrap(), 18.to_bigint().unwrap());
        assert_eq!(n1 * n2, expected);
    }

    #[test]
    fn test_neutrosophic_pow_mod() {
        // g = 2+1I, x = 3+0I, p = 5+0I
        // Real part: 2^3 mod 5 = 8 mod 5 = 3
        // Indeterminate part: ((2+1)^(3+0) mod (5+0)) - 3 = (3^3 mod 5) - 3 = (27 mod 5) - 3 = 2 - 3 = -1
        let g = NeutrosophicNumber::new(2.to_bigint().unwrap(), 1.to_bigint().unwrap());
        let x = NeutrosophicNumber::new(3.to_bigint().unwrap(), 0.to_bigint().unwrap());
        let p = NeutrosophicNumber::new(5.to_bigint().unwrap(), 0.to_bigint().unwrap());
        let expected = NeutrosophicNumber::new(3.to_bigint().unwrap(), (-1).to_bigint().unwrap());
        assert_eq!(g.pow_mod(&x, &p), expected);
    }
}
