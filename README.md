# schnorr-bip340

BIP-340 Schnorr signatures over secp256k1, implemented in pure Python
(zero dependencies). This is the signature scheme behind Bitcoin
Taproot (BIP-341/342).

## What's here

- `schnorr.py` — reference-style implementation of the BIP-340 `sign`
  and `verify` algorithms, plus helpers: point arithmetic over
  secp256k1, `lift_x` (x-coordinate → even-y point), and BIP-340
  `tagged_hash` (SHA-256 based domain separation).
- Signatures are 64 bytes: `R_x (32) || s (32)`; public keys are the
  32-byte x-only coordinate.
- The doctests embed official test vectors from
  [bip-0340/test-vectors.csv](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv),
  including the empty-message vector and failure cases.

## Usage

```python
from schnorr import schnorr_sign, schnorr_verify, pubkey_from_secret

sk = bytes.fromhex("...")           # 32 bytes, 1 <= int(sk) <= n-1
pk = pubkey_from_secret(sk)         # 32-byte x-only public key

import os
sig = schnorr_sign(sk, b"hello taproot", aux_rand=os.urandom(32))
assert schnorr_verify(pk, sig, b"hello taproot")
```

CLI:

```bash
python schnorr.py --demo   # sign/verify demo with a fixed test key
python schnorr.py --test   # run the doctests (BIP-340 vectors + round trips)
```

## Notes

- This is educational code — slow (schoolbook 256-step scalar
  multiplication) and not hardened against side channels. Don't use it
  with real funds.
- Why Schnorr over ECDSA? Linearity enables signature aggregation and
  compact multisig (e.g. MuSig2), and verification is batch-friendly.
