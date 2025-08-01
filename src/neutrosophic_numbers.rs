use num_bigint::{BigInt, RandBigInt, ToBigInt};
use rand::Rng;
use std::ops::{Add, Mul};

/// Represents a neutrosophic number of the form `a + bI`.
///
/// In the context of this cryptographic protocol, `I` is an indeterminacy
/// symbol with the algebraic property I^2 = I. The numbers `a` and `b`
/// are large integers, suitable for cryptographic calculations.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NeutrosophicNumber {
    /// The real part of the neutrosophic number.
    pub a: BigInt,
    /// The coefficient of the indeterminate part `I`.
    pub b: BigInt,
}

impl NeutrosophicNumber {
    /// Constructs a new `NeutrosophicNumber`.
    ///
    /// # Arguments
    ///
    /// * `a` - The real part.
    /// * `b` - The indeterminate part's coefficient.
    pub fn new(a: BigInt, b: BigInt) -> Self {
        NeutrosophicNumber { a, b }
    }

    /// Checks if the neutrosophic number is positive.
    ///
    /// According to neutrosophic number theory, a number `a + bI` is positive
    /// if and only if `a > 0` and `a + b > 0`.
    pub fn is_positive(&self) -> bool {
        self.a > BigInt::from(0) && (&self.a + &self.b) > BigInt::from(0)
    }

    /// Performs modular exponentiation on neutrosophic numbers.
    ///
    /// This method implements the specific formula for neutrosophic modular exponentiation
    /// required by the N-1-R ZKP protocol.
    ///
    /// Formula: `(g1 + g2*I)^(x1 + x2*I) mod (p1 + p2*I)` is calculated as:
    /// `g1^x1 (mod p1) + I * [((g1+g2)^(x1+x2) (mod p1+p2)) - (g1^x1 (mod p1))]`
    ///
    /// # Arguments
    ///
    /// * `self` - The base `g` of the exponentiation.
    /// * `exp` - The exponent `x`.
    /// * `modulus` - The modulus `p`.
    pub fn pow_mod(&self, exp: &Self, modulus: &Self) -> Self {
        let g1: &BigInt = &self.a;
        let g2: &BigInt = &self.b;
        let x1: &BigInt = &exp.a;
        let x2: &BigInt = &exp.b;
        let p1: &BigInt = &modulus.a;
        let p2: &BigInt = &modulus.b;

        // Calculate the real part: g1^x1 (mod p1)
        let term1: BigInt = g1.modpow(x1, p1);

        // Calculate the components for the indeterminate part.
        let base_sum: BigInt = g1 + g2;
        let exp_sum: BigInt = x1 + x2;
        let modulus_sum: BigInt = p1 + p2;

        // Calculate the main term of the indeterminate part: (g1+g2)^(x1+x2) (mod p1+p2)
        let term2_base: BigInt = base_sum.modpow(&exp_sum, &modulus_sum);

        // The final value for the indeterminate part's coefficient.
        let term_i_val: BigInt = term2_base - &term1;

        NeutrosophicNumber::new(term1, term_i_val)
    }
}

/// Implements the addition operator `+` for `NeutrosophicNumber`.
///
/// Addition is performed element-wise: `(a + bI) + (c + dI) = (a+c) + (b+d)I`.
impl Add for NeutrosophicNumber {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        NeutrosophicNumber::new(self.a + other.a, self.b + other.b)
    }
}

/// Implements the multiplication operator `*` for `NeutrosophicNumber`.
///
/// Multiplication is defined by the property I^2 = I:
/// `(a + bI) * (c + dI) = ac + (ad + bc + bd)I`.
impl Mul for NeutrosophicNumber {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let ac = &self.a * &other.a;
        let ad = &self.a * &other.b;
        let bc = &self.b * &other.a;
        let bd = &self.b * &other.b;
        NeutrosophicNumber::new(ac, ad + bc + bd)
    }
}

/// Generates a random `NeutrosophicNumber` with components of a given bit size.
///
/// This is a utility function for creating keys or other random values for the protocol.
///
/// # Arguments
///
/// * `rng` - A mutable reference to a random number generator.
/// * `bit_size` - The desired bit size for the `a` and `b` components.
pub fn generate_random_neutrosophic<R: Rng + RandBigInt>(
    rng: &mut R,
    bit_size: usize,
) -> NeutrosophicNumber {
    let bit_size_u64 = bit_size as u64;
    // `gen_biguint` ensures the generated components are non-negative.
    let a_val = rng.gen_biguint(bit_size_u64).to_bigint().unwrap();
    let b_val = rng.gen_biguint(bit_size_u64).to_bigint().unwrap();
    NeutrosophicNumber::new(a_val, b_val)
}
