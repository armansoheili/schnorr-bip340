"""BIP-340 Schnorr signatures over secp256k1, in pure Python (no dependencies).

Implements the reference algorithms from BIP-340
(https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki):
``schnorr_sign`` and ``schnorr_verify``, plus the underlying helpers
(``lift_x``, ``tagged_hash``, point arithmetic over secp256k1).

Schnorr is the signature scheme behind Bitcoin Taproot (BIP-341/342):
64-byte signatures, linear so they support aggregation and multisig
schemes such as MuSig2.

Run ``python schnorr.py --test`` to run the doctests (which embed
official BIP-340 test vectors), or ``python schnorr.py --demo`` for a
short sign/verify demonstration.

>>> from schnorr import schnorr_sign, schnorr_verify, pubkey_from_secret
>>> sk = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000003")
>>> pubkey_from_secret(sk).hex().upper()
'F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9'

Sign BIP-340 test vector 0 (deterministic aux_rand = 32 zero bytes):

>>> aux = bytes(32)
>>> msg = bytes(32)
>>> sig = schnorr_sign(sk, msg, aux_rand=aux)
>>> sig.hex().upper() == "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
True
>>> pk = bytes.fromhex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
>>> schnorr_verify(pk, sig, msg)
True

Sign BIP-340 test vector 1:

>>> sk = bytes.fromhex("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF")
>>> pubkey_from_secret(sk).hex().upper()
'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659'
>>> aux = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
>>> msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
>>> sig = schnorr_sign(sk, msg, aux_rand=aux)
>>> sig.hex().upper() == "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"
True

Empty message is legal (BIP-340 vector 15):

>>> sk = bytes.fromhex("0340034003400340034003400340034003400340034003400340034003400340")
>>> aux = bytes(32)
>>> sig = schnorr_sign(sk, b"", aux_rand=aux)
>>> sig.hex().upper() == "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63"
True
>>> pk = bytes.fromhex("778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117")
>>> schnorr_verify(pk, sig, b"")
True

Verification must fail for a non-curve public key (BIP-340 vector 5):

>>> pk = bytes.fromhex("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
>>> msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
>>> bad = bytes.fromhex("6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B")
>>> schnorr_verify(pk, bad, msg)
False

Round-trip: fresh random key, sign, verify, tamper, re-verify:

>>> import os
>>> sk = os.urandom(32); pk = pubkey_from_secret(sk)
>>> sig = schnorr_sign(sk, b"hello taproot")
>>> schnorr_verify(pk, sig, b"hello taproot")
True
>>> tampered = bytes([sig[0] ^ 1]) + sig[1:]
>>> schnorr_verify(pk, tampered, b"hello taproot")
False

Signing with a secret key outside [1, n-1] raises:

>>> schnorr_sign(bytes(32), b"x")
Traceback (most recent call last):
ValueError: secret key out of range: must be in [1, n-1]
"""

import hashlib
import os

__all__ = [
    "schnorr_sign",
    "schnorr_verify",
    "pubkey_from_secret",
    "lift_x",
    "tagged_hash",
    "point_add",
    "point_mul",
    "P",
    "N",
    "G",
]

# Field and curve order for secp256k1.
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# secp256k1 generator point.
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def point_add(p1, p2):
    """Add two curve points (or the point at infinity, represented as None)."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] != p2[1]:
        return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0]) * pow(2 * p1[1], P - 2, P) % P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], P - 2, P) % P
    x3 = (lam * lam - p1[0] - p2[0]) % P
    return (x3, (lam * (p1[0] - x3) - p1[1]) % P)


def point_mul(p, scalar):
    """Multiply point p by a scalar (double-and-add)."""
    result = None
    for bit in range(256):
        if (scalar >> bit) & 1:
            result = point_add(result, p)
        p = point_add(p, p)
    return result


def has_even_y(point):
    """True if point is not infinity and has an even Y coordinate."""
    return point is not None and point[1] % 2 == 0


def lift_x(x):
    """Recover a curve point from its x-coordinate (the one with even Y)."""
    if x >= P:
        return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    return (x, y if y % 2 == 0 else P - y)


def tagged_hash(tag, msg):
    """BIP-340 tagged hash: SHA256(SHA256(tag)||SHA256(tag)||msg)."""
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def bytes_from_int(x):
    return x.to_bytes(32, "big")


def int_from_bytes(b):
    return int.from_bytes(b, "big")


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def pubkey_from_secret(sk):
    """Return the 32-byte x-only public key for a 32-byte secret key."""
    d = int_from_bytes(sk)
    if not 1 <= d <= N - 1:
        raise ValueError("secret key out of range: must be in [1, n-1]")
    point = point_mul(G, d)
    return bytes_from_int(point[0])


def schnorr_sign(sk, msg, aux_rand=None):
    """Create a 64-byte BIP-340 Schnorr signature.

    ``sk`` is 32 bytes with 1 <= int(sk) <= n-1. ``msg`` is an arbitrary
    byte string (BIP-340 allows any length, including empty). ``aux_rand``
    is 32 bytes of fresh randomness for side-channel protection; pass a
    fixed value (e.g. ``bytes(32)``) for deterministic test vectors.
    """
    d = int_from_bytes(sk)
    if not 1 <= d <= N - 1:
        raise ValueError("secret key out of range: must be in [1, n-1]")
    point = point_mul(G, d)
    assert point is not None
    if not has_even_y(point):
        d = N - d
    if aux_rand is None:
        aux_rand = os.urandom(32)
    t = xor_bytes(bytes_from_int(d), tagged_hash("BIP0340/aux", aux_rand))
    rand = tagged_hash("BIP0340/nonce", t + bytes_from_int(point[0]) + msg)
    k0 = int_from_bytes(rand) % N
    if k0 == 0:
        raise RuntimeError("signing failed: nonce k0 = 0 (retry with new aux_rand)")
    r_point = point_mul(G, k0)
    assert r_point is not None
    k = N - k0 if not has_even_y(r_point) else k0
    e = (
        int_from_bytes(
            tagged_hash(
                "BIP0340/challenge",
                bytes_from_int(r_point[0]) + bytes_from_int(point[0]) + msg,
            )
        )
        % N
    )
    return bytes_from_int(r_point[0]) + bytes_from_int((k + e * d) % N)


def schnorr_verify(pk, sig, msg):
    """Verify a 64-byte BIP-340 Schnorr signature. Returns True/False."""
    if len(pk) != 32 or len(sig) != 64:
        return False
    point = lift_x(int_from_bytes(pk))
    r = int_from_bytes(sig[0:32])
    s = int_from_bytes(sig[32:64])
    if point is None or r >= P or s >= N:
        return False
    e = int_from_bytes(tagged_hash("BIP0340/challenge", sig[0:32] + pk + msg)) % N
    r_point = point_add(point_mul(G, s), point_mul(point, N - e))
    return r_point is not None and has_even_y(r_point) and r_point[0] == r


def _demo():
    sk = bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000003"
    )
    pk = pubkey_from_secret(sk)
    aux = bytes(32)  # deterministic demo; use os.urandom(32) for real signing
    msg = b"taproot leaves"
    sig = schnorr_sign(sk, msg, aux_rand=aux)
    print("secret key:", sk.hex())
    print("public key:", pk.hex())
    print("message:   ", msg.decode())
    print("signature: ", sig.hex())
    print("verify:    ", schnorr_verify(pk, sig, msg))
    print("tampered:  ", schnorr_verify(pk, sig[:-1] + bytes([sig[-1] ^ 1]), msg))


def _test():
    import doctest

    results = doctest.testmod(verbose=False)
    print("doctests: %d passed, %d failed" % (results.attempted - results.failed, results.failed))
    return results.failed


if __name__ == "__main__":
    import sys

    if "--demo" in sys.argv:
        _demo()
    elif "--test" in sys.argv:
        sys.exit(1 if _test() else 0)
    else:
        print(__doc__)
