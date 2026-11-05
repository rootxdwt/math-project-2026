import argparse
import base64
import json
import glob
import os
import sys

# Ensure local imports work regardless of working directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_utils import (
    is_prime,
    rsa_decrypt_bytes,
    decrypt_aes_ecb,
    parse_int_or_b64,
)


def factor_modulus(n: int) -> tuple[int, int]:
    """
    Factors modulus n = p * q where p, q are prime numbers between 400 and 500.
    Since p, q in [400, 500], we can quickly factor by trial division.
    """
    for candidate in range(400, 501):
        if n % candidate == 0:
            p = candidate
            q = n // candidate
            return p, q
    # Fallback to general trial division if outside [400, 500]
    for candidate in range(2, int(n**0.5) + 1):
        if n % candidate == 0:
            return candidate, n // candidate
    raise ValueError(f"Could not factor modulus n={n}")


def crack_protocol_two(messages: list[dict]) -> dict:
    """
    Additional Task I: Passive attack on Protocol II (RSA + AES).
    1. Intercepts public key e and modulus n from Message 1 (Bob -> Alice).
    2. Factors n = p * q to find private key d = e^(-1) mod (p-1)(q-1).
    3. Intercepts RSA-encrypted key list from Message 2 (Alice -> Bob).
    4. Decrypts symmetric key with d.
    5. Decrypts subsequent AES-encrypted messages from Bob and Alice.
    """
    results = {"protocol": "Protocol II (RSA)", "decrypted_messages": []}

    pub_msg = None
    enc_key_msg = None
    aes_messages = []

    for msg in messages:
        msg_type = msg.get("type")
        opcode = msg.get("opcode")
        if msg_type == "RSA" and opcode == 1:
            pub_msg = msg
        elif msg_type == "RSA" and opcode == 2 and "encrypted_key" in msg:
            enc_key_msg = msg
        elif msg_type == "AES" and opcode == 2 and "encryption" in msg:
            aes_messages.append(msg)

    if not pub_msg or not enc_key_msg:
        raise ValueError("Log does not contain sufficient RSA messages for Protocol II attack")

    e = parse_int_or_b64(pub_msg["public"])
    n = pub_msg["parameter"]["n"]

    # Factor n
    p, q = factor_modulus(n)
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    # Decrypt symmetric key
    encrypted_key = enc_key_msg["encrypted_key"]
    sym_key = rsa_decrypt_bytes(encrypted_key, d, n)
    results["symmetric_key_hex"] = sym_key.hex()
    results["p"] = p
    results["q"] = q
    results["d"] = d

    # Decrypt all intercepted AES messages
    for idx, aes_msg in enumerate(aes_messages, start=1):
        plaintext = decrypt_aes_ecb(sym_key, aes_msg["encryption"])
        sender = "Bob" if idx % 2 == 1 else "Alice"
        results["decrypted_messages"].append({"index": idx, "sender": sender, "plaintext": plaintext})

    return results


def crack_protocol_three(messages: list[dict]) -> dict:
    """
    Additional Task II: Passive attack on Protocol III (Diffie-Hellman + AES).
    1. Intercepts DH parameters (p, g) and Bob's public key B from Message 1.
    2. Intercepts Alice's public key A from Message 2.
    3. Solves the discrete logarithm problem g^b = B (mod p) via brute force
       (p in [400, 500] is small enough to solve instantaneously).
    4. Derives DH shared secret S = A^b mod p.
    5. Extracts 32-byte AES key and decrypts intercepted AES messages.
    """
    results = {"protocol": "Protocol III (DH)", "decrypted_messages": []}

    bob_dh_msg = None
    alice_dh_msg = None
    aes_messages = []

    for msg in messages:
        msg_type = msg.get("type")
        opcode = msg.get("opcode")
        if msg_type == "DH" and opcode == 1 and "parameter" in msg:
            bob_dh_msg = msg
        elif msg_type == "DH" and opcode == 1 and "parameter" not in msg:
            alice_dh_msg = msg
        elif msg_type == "AES" and opcode == 2 and "encryption" in msg:
            aes_messages.append(msg)

    if not bob_dh_msg or not alice_dh_msg:
        raise ValueError("Log does not contain sufficient DH messages for Protocol III attack")

    p = bob_dh_msg["parameter"]["p"]
    g = bob_dh_msg["parameter"]["g"]
    bob_pub = parse_int_or_b64(bob_dh_msg["public"])
    alice_pub = parse_int_or_b64(alice_dh_msg["public"])

    # Solve discrete logarithm g^b = bob_pub (mod p)
    b = None
    for candidate_b in range(1, p):
        if pow(g, candidate_b, p) == bob_pub:
            b = candidate_b
            break

    if b is None:
        raise ValueError(f"Could not solve discrete log for g={g}, B={bob_pub}, p={p}")

    shared_secret = pow(alice_pub, b, p)
    aes_key = shared_secret.to_bytes(2, byteorder="big") * 16

    results["p"] = p
    results["g"] = g
    results["b"] = b
    results["shared_secret"] = shared_secret
    results["aes_key_hex"] = aes_key.hex()

    for idx, aes_msg in enumerate(aes_messages, start=1):
        plaintext = decrypt_aes_ecb(aes_key, aes_msg["encryption"])
        sender = "Bob" if idx % 2 == 1 else "Alice"
        results["decrypted_messages"].append({"index": idx, "sender": sender, "plaintext": plaintext})

    return results


def analyze_log_file(filepath: str):
    print(f"\n{'='*70}\nAnalyzing: {filepath}\n{'='*70}")
    with open(filepath, "r", encoding="utf-8") as f:
        messages = [json.loads(line) for line in f if line.strip()]

    # Determine protocol type by examining messages
    is_dh = any(msg.get("type") == "DH" for msg in messages)
    is_rsa = any(msg.get("type") == "RSA" for msg in messages)

    if is_dh:
        res = crack_protocol_three(messages)
        print(f"[*] Attacking Protocol III (Diffie-Hellman):")
        print(f"    - Modulus p: {res['p']}, Generator g: {res['g']}")
        print(f"    - Recovered Private Key b: {res['b']}")
        print(f"    - Shared Secret: {res['shared_secret']}")
        print(f"    - Derived AES Key: {res['aes_key_hex']}")
        print(f"[*] Decrypted Messages:")
        for dm in res["decrypted_messages"]:
            print(f"    [{dm['sender']}] (Msg {dm['index']}): \"{dm['plaintext']}\"")
    elif is_rsa:
        res = crack_protocol_two(messages)
        print(f"[*] Attacking Protocol II (RSA + AES):")
        print(f"    - Modulus Factorization: p={res['p']}, q={res['q']}")
        print(f"    - Recovered Private Key d: {res['d']}")
        print(f"    - Recovered Symmetric Key: {res['symmetric_key_hex']}")
        print(f"[*] Decrypted Messages:")
        for dm in res["decrypted_messages"]:
            print(f"    [{dm['sender']}] (Msg {dm['index']}): \"{dm['plaintext']}\"")
    else:
        print("[!] Unrecognized protocol in log file.")


def main():
    parser = argparse.ArgumentParser(description="Eve - Passive Attacker for Protocol II and Protocol III (Additional Tasks)")
    parser.add_argument("log_files", nargs="*", help="Path to adversarial protocol log files")
    parser.add_argument("--all", help="Analyze all adv_protocol_*.log files in directory", action="store_true")
    args = parser.parse_args()

    files = list(args.log_files)
    if args.all or not files:
        files = sorted(glob.glob("adv_protocol_*.log"))

    if not files:
        print("No log files found or specified.")
        return

    for fn in files:
        try:
            analyze_log_file(fn)
        except Exception as e:
            print(f"[!] Failed to analyze {fn}: {e}")


if __name__ == "__main__":
    main()
