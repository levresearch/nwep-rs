//! nwep shamir secret sharing, threshold split-and-recombine NW150400.
//!
//! [split] cuts a secret into n shares so any t of them reconstruct it and t-1
//! reveal nothing; [combine] reconstructs from a quorum. the intended use is an
//! offline recovery key. shares and reconstructed secrets are key material  -  the
//! returned vectors should be zeroized before they drop (the library does not own
//! them).

use crate::error::{Error, Result};
use core::ptr;
use nwep_sys as sys;

/// splits secret into n shares, any t of which reconstruct it NW150400.
///
/// each returned share is 1 + secret.len() bytes (a 1-based index byte plus
/// data). the shares are key material, zeroize them before they drop.
///
/// returns the n shares.
/// errors [Error::ConfigInvalid] when the bounds are bad (need 2 <= t <= n <= 255).
pub fn split(secret: &[u8], t: usize, n: usize) -> Result<Vec<Vec<u8>>> {
    if !(2..=255).contains(&n) || !(2..=n).contains(&t) {
        return Err(Error::ConfigInvalid);
    }
    let mut total = 0usize;
    // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
    Error::check(unsafe {
        sys::nwep_shamir_split(
            secret.as_ptr(),
            secret.len(),
            t,
            n,
            ptr::null_mut(),
            &mut total,
        )
    })?;
    let mut packed = vec![0u8; total];
    // SAFETY: buf is sized to len as returned by the probe call above.
    Error::check(unsafe {
        sys::nwep_shamir_split(
            secret.as_ptr(),
            secret.len(),
            t,
            n,
            packed.as_mut_ptr(),
            &mut total,
        )
    })?;
    packed.truncate(total);
    let share_len = 1 + secret.len();
    Ok(packed.chunks(share_len).map(|c| c.to_vec()).collect())
}

/// reconstructs the secret from a quorum of shares NW150400.
///
/// at least t shares (from the original [split]) are required for a correct
/// result. all shares must be the same length. the reconstructed secret is key
/// material, zeroize it before it drops.
///
/// returns the reconstructed secret.
/// errors [Error::ConfigInvalid] for duplicate indices, a length mismatch, or
/// fewer than two shares.
pub fn combine(shares: &[Vec<u8>]) -> Result<Vec<u8>> {
    if shares.len() < 2 {
        return Err(Error::ConfigInvalid);
    }
    let share_len = shares[0].len();
    if share_len < 2 || shares.iter().any(|s| s.len() != share_len) {
        return Err(Error::ConfigInvalid);
    }
    // the c side wants the shares packed contiguously.
    let mut packed = Vec::with_capacity(shares.len() * share_len);
    for s in shares {
        packed.extend_from_slice(s);
    }
    let mut out = vec![0u8; share_len - 1];
    let mut out_len = out.len();
    // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
    Error::check(unsafe {
        sys::nwep_shamir_combine(
            packed.as_ptr(),
            shares.len(),
            share_len,
            out.as_mut_ptr(),
            &mut out_len,
        )
    })?;
    out.truncate(out_len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_then_combine_round_trips() {
        let secret = b"web/1 offline recovery key bytes";
        let shares = split(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);
        // each share is index byte + the secret length.
        assert!(shares.iter().all(|s| s.len() == secret.len() + 1));

        // any three of the five reconstruct the secret.
        let subset = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        assert_eq!(combine(&subset).unwrap(), secret);
    }

    #[test]
    fn bad_bounds_are_rejected() {
        assert!(split(b"x", 1, 5).is_err()); // t < 2
        assert!(split(b"x", 6, 5).is_err()); // t > n
        assert!(combine(&[vec![1u8, 2]]).is_err()); // < 2 shares
    }
}
