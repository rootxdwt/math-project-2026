import subprocess
import time
import sys
import socket
import json
import threading

def run_mock_server_once(port, response_msg):
    """Simple mock server socket that receives one message and replies with response_msg."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(1)

    received_client_msg = []

    def mock_handler():
        conn, _ = server.accept()
        # Read Alice's request
        data = conn.recv(1024)
        if data:
            # Send the test response
            conn.sendall(json.dumps(response_msg).encode("utf-8"))
            # Read Alice's reply (e.g. error message)
            reply = conn.recv(1024)
            if reply:
                received_client_msg.append(json.loads(reply.decode("utf-8")))
        conn.close()
        server.close()

    t = threading.Thread(target=mock_handler)
    t.start()
    return t, received_client_msg

def test_all():
    print("=" * 60)
    print("RUNNING AUTOMATED PROTOCOL TESTS FOR ALICE & BOB")
    print("=" * 60)

    # 1. Start Bob on port 12345
    port = 12345
    bob_proc = subprocess.Popen([sys.executable, "bob.py", "-p", str(port), "-m", "HelloFromBob"])
    time.sleep(1)

    try:
        # Test 1: Protocol I (RSAKey)
        print("\n>>> Testing Protocol I (RSAKey)...")
        res1 = subprocess.run([sys.executable, "alice.py", "-a", "127.0.0.1", "-p", str(port), "-t", "1"], capture_output=True, text=True)
        print("STDOUT:\n", res1.stdout)
        assert "CORRECT" in res1.stdout, "Protocol I verification failed!"
        print("[+] Protocol I PASSED!")

        # Test 2: Protocol II (RSA)
        print("\n>>> Testing Protocol II (RSA + AES)...")
        res2 = subprocess.run([sys.executable, "alice.py", "-a", "127.0.0.1", "-p", str(port), "-t", "2", "-m", "HelloFromAlice"], capture_output=True, text=True)
        print("STDOUT:\n", res2.stdout)
        assert "HelloFromBob" in res2.stdout, "Protocol II decryption failed!"
        print("[+] Protocol II PASSED!")

        # Test 3: Protocol III (DH)
        print("\n>>> Testing Protocol III (DH + AES)...")
        res3 = subprocess.run([sys.executable, "alice.py", "-a", "127.0.0.1", "-p", str(port), "-t", "3", "-m", "HelloFromAliceDH"], capture_output=True, text=True)
        print("STDOUT:\n", res3.stdout)
        assert "HelloFromBob" in res3.stdout, "Protocol III decryption failed!"
        print("[+] Protocol III PASSED!")

        # Test 3b: Test Bob as server receiving invalid DH parameters (Slide 17)
        print("\n>>> Testing Bob as server receiving non-prime DH parameter (Slide 17)...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", port))
        s.sendall(json.dumps({"opcode": 1, "type": "DH", "public": 100, "parameter": {"p": 450, "g": 3}}).encode("utf-8"))
        resp = json.loads(s.recv(1024).decode("utf-8"))
        s.close()
        assert resp.get("opcode") == 3 and resp.get("error") == "incorrect prime number", "Bob failed non-prime check!"
        print("[+] Bob non-prime test PASSED! Response:", resp)

        print("\n>>> Testing Bob as server receiving non-generator DH parameter (Slide 17)...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", port))
        s.sendall(json.dumps({"opcode": 1, "type": "DH", "public": 100, "parameter": {"p": 401, "g": 1}}).encode("utf-8"))
        resp = json.loads(s.recv(1024).decode("utf-8"))
        s.close()
        assert resp.get("opcode") == 3 and resp.get("error") == "incorrect generator", "Bob failed non-generator check!"
        print("[+] Bob non-generator test PASSED! Response:", resp)

    finally:
        bob_proc.terminate()
        bob_proc.wait()

    # Test 4: Protocol IV-I (Alice receives Bad Prime)
    print("\n>>> Testing Protocol IV-I (Alice receives Incorrect Prime Number)...")
    port_bad_prime = 12346
    bad_prime_msg = {"opcode": 1, "type": "DH", "public": 189, "parameter": {"p": 450, "g": 3}}
    t4, client_reply_4 = run_mock_server_once(port_bad_prime, bad_prime_msg)
    time.sleep(0.5)

    res4 = subprocess.run([sys.executable, "alice.py", "-a", "127.0.0.1", "-p", str(port_bad_prime), "-t", "3"], capture_output=True, text=True)
    t4.join()
    print("Alice STDOUT:\n", res4.stdout)
    assert any(msg.get("opcode") == 3 and msg.get("error") == "incorrect prime number" for msg in client_reply_4), "Protocol IV-I failed!"
    print("[+] Protocol IV-I PASSED! Alice sent:", client_reply_4)

    # Test 5: Protocol IV-II (Alice receives Bad Generator)
    print("\n>>> Testing Protocol IV-II (Alice receives Incorrect Generator)...")
    port_bad_gen = 12347
    bad_gen_msg = {"opcode": 1, "type": "DH", "public": 1, "parameter": {"p": 401, "g": 1}}
    t5, client_reply_5 = run_mock_server_once(port_bad_gen, bad_gen_msg)
    time.sleep(0.5)

    res5 = subprocess.run([sys.executable, "alice.py", "-a", "127.0.0.1", "-p", str(port_bad_gen), "-t", "3"], capture_output=True, text=True)
    t5.join()
    print("Alice STDOUT:\n", res5.stdout)
    assert any(msg.get("opcode") == 3 and msg.get("error") == "incorrect generator" for msg in client_reply_5), "Protocol IV-II failed!"
    print("[+] Protocol IV-II PASSED! Alice sent:", client_reply_5)

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    test_all()
