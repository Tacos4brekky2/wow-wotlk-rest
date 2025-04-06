import hashlib
import random

def calculate_srp6_verifier(username, password):
    username = username.upper()
    password = password.upper()

    # Generate a random 32-byte salt
    salt = bytearray(random.getrandbits(8) for _ in range(32))

    # Compute h1 = SHA1(username:password)
    h1_input = f"{username}:{password}".encode('utf-8')
    h1 = hashlib.sha1(h1_input).digest()

    # Compute h2 = SHA1(salt || h1)
    h2 = hashlib.sha1(salt + h1).digest()

    # Convert h2 to a little-endian integer
    h2_int = int.from_bytes(h2[::-1], 'big')

    # SRP6 parameters
    g = 7
    N = int('894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7', 16)

    # Compute verifier = (g ^ h2) % N
    verifier_int = pow(g, h2_int, N)

    # Convert verifier back to a byte array in little-endian order
    verifier = verifier_int.to_bytes(32, 'little')

    return salt, verifier
