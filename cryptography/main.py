import threading
from entities import run_node
from rsa import generate_rsa_keys, encrypt_rsa_message, decrypt_rsa_message
from ecc import generate_ecc_keys, ecc_sign, ecc_verify
from aes import generate_aes_key, aes_encrypt, aes_decrypt, derive_aes_key

# Function to start the peer node
def start_p2p_node():
    print("\n[INFO] Starting P2P Node Configuration")
    my_port = int(input("Enter port for this node: "))
    known_peer_count = int(input("Enter number of known peers: "))
    known_peers = []

    for _ in range(known_peer_count):
        ip = input("Enter peer IP: ")
        port = int(input("Enter peer port: "))
        known_peers.append((ip, port))

    # Start the P2P node
    node_thread = threading.Thread(target=run_node, args=(my_port, known_peers))
    node_thread.daemon = True
    node_thread.start()

# Example usage of RSA
def example_rsa_usage():
    private_key, public_key = generate_rsa_keys()
    message = "Test RSA encryption"
    encrypted_message = encrypt_rsa_message(public_key, message)
    decrypted_message = decrypt_rsa_message(private_key, encrypted_message)
    print("\n--- RSA Example ---")
    print("Original Message:", message)
    print("Decrypted Message:", decrypted_message)

# Example usage of ECC
def example_ecc_usage():
    private_key, public_key = generate_ecc_keys()
    message = "Test ECC signing"
    signature = ecc_sign(private_key, message)
    is_valid = ecc_verify(public_key, message, signature)
    print("\n--- ECC Example ---")
    print("Signature valid:", is_valid)

# Example usage of AES
def example_aes_usage():
    password = "example_password"
    aes_key = derive_aes_key(password)
    message = "Test AES encryption"
    encrypted = aes_encrypt(aes_key, message)
    print("\n--- AES Example ---")
    print(f"Encrypted Message (hex): {encrypted['ciphertext'].hex()}")
    print("Decrypted Message:", aes_decrypt(
        aes_key, encrypted['nonce'], encrypted['ciphertext'], encrypted['tag']
    ))

# Main interactive menu
if __name__ == "__main__":
    print("=== P2P Node with Cryptographic Functions ===")
    
    # Start P2P node in a thread
    start_p2p_node()
    
    # Interactive options
    while True:
        print("\nOptions:")
        print("1. RSA Example")
        print("2. ECC Example")
        print("3. AES Example")
        print("4. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            example_rsa_usage()
        elif choice == "2":
            example_ecc_usage()
        elif choice == "3":
            example_aes_usage()
        elif choice == "4":
            print("Exiting program...")
            break
        else:
            print("Invalid choice. Please try again.")