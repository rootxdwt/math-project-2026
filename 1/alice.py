import socket
import argparse
import logging
import random
import sys
import os

# Ensure local imports work regardless of working directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_utils import (
    is_prime,
    is_generator,
    generate_dh_keypair,
    compute_dh_aes_key,
    encrypt_aes_ecb,
    decrypt_aes_ecb,
    rsa_encrypt_bytes,
    verify_rsa_keypair,
    JsonSocket,
    parse_int_or_b64,
)


def run_protocol_rsa_key(jsock: JsonSocket):
    """
    Protocol I: RSA Key Generation & Verification
    1. Alice sends {"opcode": 0, "type": "RSAKey"}
    2. Bob replies with prime numbers and keys:
       {"opcode": 0, "type": "RSAKey", "private": ..., "public": ..., "parameter": {"p": ..., "q": ...}}
    3. Alice conducts primality test on p and q.
    4. Alice verifies the RSA keypair.
    5. Alice prints the keypair with their correctness.
    """
    logging.info("[*] Starting Protocol I (RSAKey)")
    req = {"opcode": 0, "type": "RSAKey"}
    jsock.send(req)

    reply = jsock.recv()
    if not reply:
        logging.error("No reply received from Bob")
        return

    if reply.get("opcode") == 3:
        logging.error("[*] Error from Bob: {}".format(reply.get("error")))
        return

    p = reply.get("parameter", {}).get("p")
    q = reply.get("parameter", {}).get("q")
    e = parse_int_or_b64(reply.get("public"))
    d = parse_int_or_b64(reply.get("private"))

    # Conduct primality test on p and q respectively
    is_p_prime = is_prime(p) if p is not None else False
    is_q_prime = is_prime(q) if q is not None else False

    # Verify RSA keypair
    keypair_correct = False
    if p is not None and q is not None and e is not None and d is not None:
        keypair_correct = verify_rsa_keypair(p, q, e, d)

    # Print keypair with their correctness
    print(f"[*] Primality test for p={p}: {'PRIME' if is_p_prime else 'NOT PRIME'}")
    print(f"[*] Primality test for q={q}: {'PRIME' if is_q_prime else 'NOT PRIME'}")
    print(f"[*] RSA Keypair - Public: {e}, Private: {d}")
    print(f"[*] RSA Keypair verification: {'CORRECT' if keypair_correct else 'INCORRECT'}")

    logging.info("[*] Primality test for p={}: {}".format(p, is_p_prime))
    logging.info("[*] Primality test for q={}: {}".format(q, is_q_prime))
    logging.info("[*] RSA Keypair: Public (e)={}, Private (d)={}".format(e, d))
    logging.info("[*] RSA Keypair Correctness: {}".format("CORRECT" if keypair_correct else "INCORRECT"))


def run_protocol_rsa(jsock: JsonSocket, message: str = "world"):
    """
    Protocol II: RSA + AES Hybrid Encryption
    1. Alice sends {"opcode": 0, "type": "RSA"}
    2. Bob replies with public key and n:
       {"opcode": 1, "type": "RSA", "public": ..., "parameter": {"n": ...}}
    3. Alice fetches n and e, generates a random 32-byte symmetric key,
       and encrypts it per byte using RSA.
    4. Alice sends {"opcode": 2, "type": "RSA", "encrypted_key": [...]}
    5. Bob encrypts his input message using AES-ECB, base64 encodes it, and sends:
       {"opcode": 2, "type": "AES", "encryption": "..."}
    6. Alice decrypts Bob's message and prints it.
    7. Alice encrypts her input message using AES-ECB, base64 encodes it, and sends:
       {"opcode": 2, "type": "AES", "encryption": "..."}
    """
    logging.info("[*] Starting Protocol II (RSA)")
    req = {"opcode": 0, "type": "RSA"}
    jsock.send(req)

    reply = jsock.recv()
    if not reply:
        logging.error("No reply received from Bob")
        return

    if reply.get("opcode") == 3:
        logging.error("[*] Error from Bob: {}".format(reply.get("error")))
        return

    e = parse_int_or_b64(reply.get("public"))
    n = reply.get("parameter", {}).get("n")
    if e is None or n is None:
        logging.error("Invalid RSA parameters received: e={}, n={}".format(e, n))
        return

    # Generate random 32-byte (256-bit) symmetric key
    sym_key = random.randbytes(32)

    # Encrypt the random symmetric key per byte using RSA
    encrypted_key = rsa_encrypt_bytes(sym_key, e, n)
    jsock.send({"opcode": 2, "type": "RSA", "encrypted_key": encrypted_key})

    # Receive Bob's AES-encrypted message
    bob_enc_msg = jsock.recv()
    if not bob_enc_msg:
        logging.error("No encrypted message received from Bob")
        return

    if bob_enc_msg.get("opcode") == 3:
        logging.error("[*] Error from Bob: {}".format(bob_enc_msg.get("error")))
        return

    decrypted_bob = decrypt_aes_ecb(sym_key, bob_enc_msg["encryption"])
    print("[*] Decrypted message from Bob: {}".format(decrypted_bob))
    logging.info("[*] Decrypted: {}".format(decrypted_bob))

    # Encrypt Alice's input message and send to Bob
    alice_enc = encrypt_aes_ecb(sym_key, message)
    jsock.send({"opcode": 2, "type": "AES", "encryption": alice_enc})


def run_protocol_dh(jsock: JsonSocket, message: str = "world"):
    """
    Protocol III & IV: Diffie-Hellman Key Exchange & Error Control
    1. Alice sends {"opcode": 0, "type": "DH"}
    2. Bob replies with DH parameters and public key:
       {"opcode": 1, "type": "DH", "public": ..., "parameter": {"p": ..., "g": ...}}
    3. Alice conducts primality test on p.
       If non-prime: Alice sends {"opcode": 3, "error": "incorrect prime number"},
       prints error, and exits.
    4. Alice verifies whether g is the correct generator of Z_p*.
       If non-generator: Alice sends {"opcode": 3, "error": "incorrect generator"},
       prints error, and exits.
    5. Alice generates DH keypair, sends {"opcode": 1, "type": "DH", "public": A}.
    6. Alice generates DH shared secret, derives 32-byte AES key.
    7. Alice receives Bob's AES-encrypted message, decrypts and prints it.
    8. Alice encrypts her input message with AES and sends it to Bob.
    """
    logging.info("[*] Starting Protocol III / IV (DH)")
    req = {"opcode": 0, "type": "DH"}
    jsock.send(req)

    reply = jsock.recv()
    if not reply:
        logging.error("No reply received from Bob")
        return

    if reply.get("opcode") == 3:
        logging.error("[*] Error from Bob: {}".format(reply.get("error")))
        return

    p = reply.get("parameter", {}).get("p")
    g = reply.get("parameter", {}).get("g")
    bob_pub = parse_int_or_b64(reply.get("public"))

    # Protocol IV-I: Primality test on received prime number
    if p is None or not is_prime(p):
        err_msg = {"opcode": 3, "error": "incorrect prime number"}
        jsock.send(err_msg)
        print("incorrect prime number")
        logging.error("incorrect prime number")
        return

    # Protocol IV-II: Verify whether received g is the correct generator
    if g is None or not is_generator(g, p):
        err_msg = {"opcode": 3, "error": "incorrect generator"}
        jsock.send(err_msg)
        print("incorrect generator")
        logging.error("incorrect generator")
        return

    # Generate Alice's DH keypair
    alice_priv, alice_pub = generate_dh_keypair(p, g)
    jsock.send({"opcode": 1, "type": "DH", "public": alice_pub})

    # Generate DH shared secret and derive 32-byte AES key
    aes_key = compute_dh_aes_key(bob_pub, alice_priv, p)

    # Receive Bob's AES-encrypted message
    bob_enc_msg = jsock.recv()
    if not bob_enc_msg:
        logging.error("No encrypted message received from Bob")
        return

    if bob_enc_msg.get("opcode") == 3:
        print("[*] Received error: {}".format(bob_enc_msg.get("error")))
        logging.error("[*] Received error: {}".format(bob_enc_msg.get("error")))
        return

    decrypted_bob = decrypt_aes_ecb(aes_key, bob_enc_msg["encryption"])
    print("[*] Decrypted message from Bob: {}".format(decrypted_bob))
    logging.info("[*] Decrypted: {}".format(decrypted_bob))

    # Encrypt Alice's input message and send to Bob
    alice_enc = encrypt_aes_ecb(aes_key, message)
    jsock.send({"opcode": 2, "type": "AES", "encryption": alice_enc})


def run(addr: str, port: int, proto_type: int = 1, message: str = "world"):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))

    jsock = JsonSocket(conn)
    try:
        norm_type = str(proto_type).strip().upper()
        if norm_type in ("1",  "I"):
            run_protocol_rsa_key(jsock)
        elif norm_type in ("2", "II"):
            run_protocol_rsa(jsock, message)
        elif norm_type in ("3", "4", "III", "IV"):
            run_protocol_dh(jsock, message)
        else:
            logging.warning("Unknown protocol number '{}', defaulting to 1 (RSAKey)".format(proto_type))
            run_protocol_rsa_key(jsock)
    finally:
        jsock.close()


def command_line_args():
    parser = argparse.ArgumentParser(description="Alice - Client for Cryptographic Protocols")
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-t", "--type", metavar="<protocol number (1/2/3)>", help="Protocol number: 1 (Protocol I: RSAKey), 2 (Protocol II: RSA), 3 (Protocol III/IV: DH)", type=int, default=1, choices=[1, 2, 3])
    parser.add_argument("-m", "--message", metavar="<message>", help="Input message to send", type=str, default="world")
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args


def main():
    args = command_line_args()
    log_level = getattr(logging, args.log.upper(), logging.INFO)
    logging.basicConfig(level=log_level, format="%(asctime)s [%(levelname)s] %(message)s")

    run(args.addr, args.port, proto_type=args.type, message=args.message)


if __name__ == "__main__":
    main()
