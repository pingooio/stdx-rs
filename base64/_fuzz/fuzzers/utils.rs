extern crate rand;
extern crate rand_pcg;

use base64::{alphabet, engine::{self, general_purpose}};
use crypto::{sha2::Sha256, Hasher};
use self::rand::{Rng, SeedableRng};
use self::rand_pcg::Pcg32;

pub fn random_engine(data: &[u8]) -> general_purpose::GeneralPurpose {
    // use sha256 of data as rng seed so it's repeatable
    let sha = Sha256::hash(data);

    let mut seed: [u8; 16] = [0; 16];
    seed.copy_from_slice(&sha.as_ref()[0..16]);

    let mut rng = Pcg32::from_seed(seed);

    let alphabet = if rng.r#gen() {
        alphabet::URL_SAFE
    } else {
        alphabet::STANDARD
    };

    let encode_padding = rng.r#gen();
    let decode_padding = if encode_padding {
        engine::DecodePaddingMode::RequireCanonical
    } else {
        engine::DecodePaddingMode::RequireNone
    };
    let config = general_purpose::GeneralPurposeConfig::new()
        .with_encode_padding(encode_padding)
        .with_decode_allow_trailing_bits(rng.r#gen())
        .with_decode_padding_mode(decode_padding);

    general_purpose::GeneralPurpose::new(&alphabet, config)
}
