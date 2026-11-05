import socket
import threading
import argparse
import logging
import sys
import os

# Ensure local imports work regardless of working directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_utils import (
    is_prime,
    is_generator,
    generate_rsa_keypair,
    generate_dh_parameters,
    generate_dh_keypair,
    compute_dh_aes_key,
    encrypt_aes_ecb,
    decrypt_aes_ecb,
    rsa_decrypt_bytes,
    JsonSocket,
    parse_int_or_b64,
)


def handle_protocol_rsa_key(jsock: JsonSocket, first_msg: dict):
    """
    Protocol I: RSA Key Generation
    Bob generates RSA keypair with p, q in [400, 500].
    Bob replies with {opcode: 0, type: "RSAKey", private: d, public: e, parameter: {p, q}}.
    """
    logging.info("[*] Executing Protocol I (RSAKey)")
    p, q, n, e, d = generate_rsa_keypair(400, 500)
    reply = {
        "opcode": 0,
        "type": "RSAKey",
        "private": d,
        "public": e,
        "parameter": {"p": p, "q": q},
    }
    jsock.send(reply)


def handle_protocol_rsa(jsock: JsonSocket, first_msg: dict, message: str = "hello"):
    """
    Protocol II: RSA + AES Hybrid Encryption
    1. Bob generates RSA keypair and sends {opcode: 1, type: "RSA", public: e, parameter: {n: n}}.
    2. Bob receives RSA-encrypted 32-byte symmetric key from Alice:
       {opcode: 2, type: "RSA", encrypted_key: [...]}.
    3. Bob decrypts the symmetric key.
    4. Bob encrypts his input message using AES-ECB, base64 encodes, and sends:
       {opcode: 2, type: "AES", encryption: "..."}.
    5. Bob receives Alice's AES-encrypted message, decrypts and prints it.
    """
    logging.info("[*] Executing Protocol II (RSA)")
    p, q, n, e, d = generate_rsa_keypair(400, 500)
    reply = {
        "opcode": 1,
        "type": "RSA",
        "public": e,
        "parameter": {"n": n},
    }
    jsock.send(reply)

    # Receive RSA-encrypted symmetric key from Alice
    enc_key_msg = jsock.recv()
    if not enc_key_msg:
        logging.error("No encrypted key received from Alice")
        return

    if enc_key_msg.get("opcode") == 3:
        logging.error("[*] Error from Alice: {}".format(enc_key_msg.get("error")))
        return

    enc_key_list = enc_key_msg.get("encrypted_key", [])
    sym_key = rsa_decrypt_bytes(enc_key_list, d, n)

    # Encrypt Bob's input message and send to Alice
    bob_enc = encrypt_aes_ecb(sym_key, message)
    jsock.send({"opcode": 2, "type": "AES", "encryption": bob_enc})

    # Receive Alice's AES-encrypted message
    alice_enc_msg = jsock.recv()
    if not alice_enc_msg:
        logging.error("No encrypted message received from Alice")
        return

    if alice_enc_msg.get("opcode") == 3:
        logging.error("[*] Error from Alice: {}".format(alice_enc_msg.get("error")))
        return

    decrypted_alice = decrypt_aes_ecb(sym_key, alice_enc_msg["encryption"])
    print("[*] Decrypted message from Alice: {}".format(decrypted_alice))
    logging.info("[*] Decrypted: {}".format(decrypted_alice))


def handle_protocol_dh(jsock: JsonSocket, first_msg: dict, message: str = "hello"):
    """
    Protocol III & IV: Diffie-Hellman Key Exchange & Error Handling
    - Normal case: Alice sends {opcode: 0, type: "DH"}.
      Bob generates p, g and keypair, sends {opcode: 1, type: "DH", public: B, parameter: {p, g}}.
      Alice replies with public key A or error opcode 3.
      Bob computes shared secret and exchanges AES encrypted messages.
    - Test case (Slide 17): Server receives DH parameters {p, g} from client.
      Bob verifies primality of p and generator g.
      Sends opcode 3 error if invalid.
    """
    logging.info("[*] Executing Protocol III / IV (DH)")

    # Check if client already provided parameters in first message (Test scenario from Slide 17)
    if first_msg.get("opcode") == 1 and "parameter" in first_msg:
        param = first_msg["parameter"]
        p = param.get("p")
        g = param.get("g")
        peer_pub = parse_int_or_b64(first_msg.get("public"))

        if p is None or not is_prime(p):
            jsock.send({"opcode": 3, "error": "incorrect prime number"})
            print("incorrect prime number")
            logging.error("incorrect prime number")
            return

        if g is None or not is_generator(g, p):
            jsock.send({"opcode": 3, "error": "incorrect generator"})
            print("incorrect generator")
            logging.error("incorrect generator")
            return

        # Valid parameters from client: generate Bob's keypair
        b_priv, b_pub = generate_dh_keypair(p, g)
        jsock.send({"opcode": 1, "type": "DH", "public": b_pub})
        aes_key = compute_dh_aes_key(peer_pub, b_priv, p)

        # Exchange AES messages
        bob_enc = encrypt_aes_ecb(aes_key, message)
        jsock.send({"opcode": 2, "type": "AES", "encryption": bob_enc})

        alice_enc_msg = jsock.recv()
        if alice_enc_msg and alice_enc_msg.get("opcode") == 2:
            decrypted_alice = decrypt_aes_ecb(aes_key, alice_enc_msg["encryption"])
            print("[*] Decrypted message from Alice: {}".format(decrypted_alice))
            logging.info("[*] Decrypted: {}".format(decrypted_alice))
        return

    # Normal initiation by Alice ({opcode: 0, type: "DH"})
    p, g = generate_dh_parameters(400, 500)

    b_priv, b_pub = generate_dh_keypair(p, g)
    reply = {
        "opcode": 1,
        "type": "DH",
        "public": b_pub,
        "parameter": {"p": p, "g": g},
    }
    jsock.send(reply)

    # Receive Alice's public key or error message
    alice_reply = jsock.recv()
    if not alice_reply:
        logging.error("No reply received from Alice")
        return

    if alice_reply.get("opcode") == 3:
        err = alice_reply.get("error", "Unknown error")
        print("[*] Received error message: {}".format(err))
        logging.info("[*] Received error message: {}".format(err))
        return

    alice_pub = parse_int_or_b64(alice_reply.get("public"))
    aes_key = compute_dh_aes_key(alice_pub, b_priv, p)

    # Send Bob's AES-encrypted message
    bob_enc = encrypt_aes_ecb(aes_key, message)
    jsock.send({"opcode": 2, "type": "AES", "encryption": bob_enc})

    # Receive Alice's AES-encrypted message
    alice_enc_msg = jsock.recv()
    if not alice_enc_msg:
        logging.error("No encrypted message received from Alice")
        return

    if alice_enc_msg.get("opcode") == 3:
        logging.error("[*] Error from Alice: {}".format(alice_enc_msg.get("error")))
        return

    decrypted_alice = decrypt_aes_ecb(aes_key, alice_enc_msg["encryption"])
    print("[*] Decrypted message from Alice: {}".format(decrypted_alice))
    logging.info("[*] Decrypted: {}".format(decrypted_alice))


def handler(conn: socket.socket, message: str = "hello"):
    jsock = JsonSocket(conn)
    try:
        first_msg = jsock.recv()
        if not first_msg:
            logging.warning("Empty initial message received")
            return

        msg_type = first_msg.get("type")
        opcode = first_msg.get("opcode")

        if opcode == 3:
            err = first_msg.get("error", "Unknown error")
            print("[*] Received error message: {}".format(err))
            logging.info("[*] Received error message: {}".format(err))
            return

        if msg_type == "RSAKey":
            handle_protocol_rsa_key(jsock, first_msg)
        elif msg_type == "RSA":
            handle_protocol_rsa(jsock, first_msg, message)
        elif msg_type == "DH":
            handle_protocol_dh(jsock, first_msg, message)
        else:
            logging.warning("Unknown message type: {}".format(msg_type))
    except Exception as e:
        logging.exception("Exception in client handler: {}".format(e))
    finally:
        jsock.close()


def run(addr: str, port: int, message: str = "hello"):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bob.bind((addr, port))

    bob.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(addr, port))

    while True:
        conn, info = bob.accept()
        logging.info("[*] Bob accepts the connection from {}:{}".format(info[0], info[1]))

        conn_handle = threading.Thread(
            target=handler,
            args=(conn, message),
        )
        conn_handle.start()


def command_line_args():
    parser = argparse.ArgumentParser(description="Bob - Server for Cryptographic Protocols")
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-m", "--message", metavar="<message>", help="Message to send", type=str, default="hello")
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args


def main():
    args = command_line_args()
    log_level = getattr(logging, args.log.upper(), logging.INFO)
    logging.basicConfig(level=log_level, format="%(asctime)s [%(levelname)s] %(message)s")

    run(args.addr, args.port, message=args.message)


if __name__ == "__main__":
    main()
