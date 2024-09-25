import os
import time
from bitcoin import random_key, privtopub, pubtoaddr, encode_pubkey
from eth_keys import keys

# Function to check if the generated address is in the list of rich addresses
def check_for_match(generated_address, rich_addresses_set):
    return generated_address in rich_addresses_set

# Load the rich addresses from the file into a set for quick lookup
def load_rich_addresses(filename):
    with open(filename, 'r') as file:
        rich_addresses = file.read().splitlines()
    return set(rich_addresses)

# Generate Ethereum address from a private key
def generate_eth_address(private_key_hex):
    private_key_bytes = bytes.fromhex(private_key_hex)
    eth_private_key = keys.PrivateKey(private_key_bytes)
    eth_address = eth_private_key.public_key.to_checksum_address()
    return eth_address

# Generate a random private key
def generate_random_private_key():
    return random_key()

# Generate a private key within a specified range
def generate_private_key_in_range(start, end):
    import random
    start_int = int(start, 16)
    end_int = int(end, 16)
    private_key_int = random.randint(start_int, end_int)
    return format(private_key_int, '064x')

# Main loop to generate keys, addresses, and compare them with rich addresses
def generate_and_compare_addresses():
    # Files for rich addresses and output
    rich_btc_addresses_file = 'addresses.txt'
    rich_eth_addresses_file = 'EthRich.txt'
    output_file = 'generated_addresses.txt'
    winner_file = 'WINNER123.txt'

    # Load rich Bitcoin and Ethereum addresses into sets
    rich_btc_addresses_set = load_rich_addresses(rich_btc_addresses_file)
    rich_eth_addresses_set = load_rich_addresses(rich_eth_addresses_file)

    # Create the output file if it doesn't exist
    if not os.path.exists(output_file):
        with open(output_file, 'w') as file:
            file.write('Private Key, Uncompressed BTC Address, Compressed BTC Address, ETH Address\n')

    # Prompt user to choose random or range-based private key generation
    choice = input("Choose key generation method (random/range): ").strip().lower()

    if choice == 'range':
        start_range = input("Enter start of range (hex format, 64 characters): ").strip()
        end_range = input("Enter end of range (hex format, 64 characters): ").strip()
    elif choice == 'random':
        start_range = end_range = None
    else:
        print("Invalid choice. Exiting.")
        return

    while True:
        # Generate a private key
        if choice == 'range':
            private_key = generate_private_key_in_range(start_range, end_range)
        else:
            private_key = generate_random_private_key()

        # Generate the uncompressed public key and Bitcoin address
        uncompressed_pub_key = privtopub(private_key)
        uncompressed_address = pubtoaddr(uncompressed_pub_key)

        # Generate the compressed public key and Bitcoin address
        compressed_pub_key = encode_pubkey(uncompressed_pub_key, 'hex_compressed')
        compressed_address = pubtoaddr(compressed_pub_key)

        # Generate the Ethereum address
        eth_address = generate_eth_address(private_key)

        # Save the generated keys and addresses to the output file
        with open(output_file, 'a') as file:
            file.write(f'{private_key}, {uncompressed_address}, {compressed_address}, {eth_address}\n')

        # Display the private key and addresses in the terminal
        print(f'Private Key: {private_key}')
        print(f'Uncompressed BTC Address: {uncompressed_address}')
        print(f'Compressed BTC Address: {compressed_address}')
        print(f'ETH Address: {eth_address}')
        print('----------------------------------------')

        # Check if the generated addresses match any rich addresses
        if (check_for_match(uncompressed_address, rich_btc_addresses_set) or 
            check_for_match(compressed_address, rich_btc_addresses_set) or 
            check_for_match(eth_address, rich_eth_addresses_set)):

            # Highlight the match in green in the terminal
            print('\033[92m' + 'MATCH FOUND!' + '\033[0m')
            print(f'Private Key: {private_key}')
            print(f'Uncompressed BTC Address: {uncompressed_address}')
            print(f'Compressed BTC Address: {compressed_address}')
            print(f'ETH Address: {eth_address}')

            # Save the winning details to the winner file
            with open(winner_file, 'w') as winner:
                winner.write(f'Private Key: {private_key}\n')
                winner.write(f'Uncompressed BTC Address: {uncompressed_address}\n')
                winner.write(f'Compressed BTC Address: {compressed_address}\n')
                winner.write(f'ETH Address: {eth_address}\n')

            # Stop the script
            break

        # Delay to avoid excessive resource usage (adjust as needed)
        time.sleep(0)

if __name__ == '__main__':
    generate_and_compare_addresses()

