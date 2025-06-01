import string, secrets, random, time
import pyargon2
from typing import Tuple

from pyargon2 import hash_bytes


class PasswordUtils:
    @staticmethod
    def generate(length: int=None, exclude_symbols: str="\"'\\`", min_len: int=12, max_len = 128) -> bytearray:
        """
            Generates a secure, random password with specified criteria.

            Args:
                length (int, optional): Desired length of the password.
                                         If None, it must be provided and meet min_len.
                exclude_symbols (str): String of symbols to exclude from password generation.
                min_len (int): Minimum allowed password length.
                max_len (int): Maximum allowed password length.

            Returns:
                bytearray: The generated password as a mutable bytearray.
                           This allows for secure zeroing of the password from memory.

            Raises:
                ValueError: If password length is out of bounds or no symbols are available.
        """
        if length is None or length < min_len:
            raise ValueError(f"Password length must be at least {min_len}")
        if length > max_len:
            raise ValueError(f"Password length cannot exceed {max_len}")

        # Define character sets for password generation
        lower = string.ascii_lowercase
        upper = string.ascii_uppercase
        digits = string.digits
        # Filter out excluded symbols from punctuation
        symbols = "".join(c for c in string.punctuation if c not in exclude_symbols)
        if not symbols:
            raise ValueError("Symbols cannot be empty after exclusions")
        all_chars = lower + upper + digits + symbols

        # Ensure the password contains at least one character from each required type
        raw_password = [
            secrets.choice(lower),
            secrets.choice(upper),
            secrets.choice(digits),
            secrets.choice(symbols),
        ]
        pass_length = length

        # Fill the rest of the password length with random choices
        while len(raw_password) < pass_length:
            new_char = secrets.choice(all_chars)

            # Avoid repeating the same character three times in a row for better randomness distribution
            if len(raw_password) >= 2 and raw_password[-1] == raw_password[-2] == new_char:
                continue
            else:
                raw_password.append(new_char)

        # Shuffle the characters to ensure random placement of the required types
        random.shuffle(raw_password)

        # Encode the password to UTF-8 bytes and store in a mutable bytearray
        password_bytes = bytearray(''.join(raw_password).encode('utf-8'))
        return password_bytes

    @staticmethod
    def hash_password(raw_password: bytearray, token_len: int=16, time_cost: int=5, memory_cost: int=131072, parallelism: int=4, hash_len: int=32) -> \
    Tuple[bytes, bytes]:
        """
            Hashes a raw password using the Argon2 algorithm.

            Args:
                raw_password (bytearray): The raw password to hash.
                token_len (int): Length of the salt to be generated in bytes.
                time_cost (int): Argon2 time cost parameter (iterations).
                memory_cost (int): Argon2 memory cost parameter (kilobytes).
                parallelism (int): Argon2 parallelism parameter (number of threads).
                hash_len (int): Desired length of the output hash in bytes.

            Returns:
                Tuple[bytes, bytes]: A tuple containing the hashed password (bytes)
                                     and the salt used (bytes).
            Raises:
                ValueError: If the password is empty or outside the allowed length range.
        """
        if len(raw_password) == 0:
            raise ValueError("Password can not be empty")
        if len(raw_password) < 12:
            raise ValueError("Password must be at least 12 characters")
        if len(raw_password) > 128:
            raise ValueError("Password cannot exceed 128 characters")

        # Generate a cryptographically strong random salt
        salt = secrets.token_bytes(token_len or 16)

        # Hash the password using Argon2 (pyargon2 library)
        hashed_password = hash_bytes(
            password=bytes(raw_password), # Convert bytearray to immutable bytes for hashing
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
        )
        return hashed_password, salt # Return both hash and salt for storage/verification

    @staticmethod
    def verify_hash(raw_password: bytearray, salt_bytes: bytes, hashed_password: bytes, time_cost: int=5, memory_cost: int=131072, parallelism: int=4, hash_len: int=32) -> bool:
        """
            Verifies a raw password against a stored hashed password and salt.

            Args:
                raw_password (bytearray): The raw password to verify.
                salt_bytes (bytes): The salt originally used for hashing.
                hashed_password (bytes): The stored hashed password to compare against.
                time_cost (int): Argon2 time cost parameter (must match original hash).
                memory_cost (int): Argon2 memory cost parameter (must match original hash).
                parallelism (int): Argon2 parallelism parameter (must match original hash).
                hash_len (int): Desired length of the output hash (must match original hash).

            Returns:
                bool: True if the raw password matches the hashed password, False otherwise.
            Raises:
                ValueError: If any required argument is missing.
        """
        if not raw_password or not salt_bytes or not hashed_password:
            raise ValueError("Missing password, salt or hashed password for verification")

        # Re-hash the provided raw password with the given salt and parameters
        expected_hashed_password = hash_bytes(
            password=bytes(raw_password),
            salt=salt_bytes,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
        )

        # Use a constant-time comparison to prevent timing attacks
        return secrets.compare_digest(hashed_password, expected_hashed_password)

    @staticmethod
    def secure_zero(*data: bytearray) -> None:
        """
            Securely zeros out the contents of one or more bytearray objects in memory.
            This helps prevent sensitive raw passwords from lingering in memory.

            Args:
                *data (bytearray): One or more bytearray objects to be zeroed out.

            Raises:
                TypeError: If any argument is not of type bytearray.
        """
        for buffer in data:
            if not isinstance(buffer, bytearray):
                raise TypeError("All arguments must be of type bytearray")
            # Overwrite the buffer with null bytes
            buffer[:] = b'\x00' * len(buffer)

if __name__ == "__main__":
    # Example usage:
    start = time.time()

    password = PasswordUtils.generate(length=16)
    print(f"Your password: {password.decode('utf-8')}")
    print(f"Password length: {len(password)}")

    hashed_password, salt = PasswordUtils.hash_password(password)
    print(f"Hashed password: {hashed_password}")
    print(f"Salt: {salt}")

    verified = PasswordUtils.verify_hash(password, salt, hashed_password)
    print(f"Password verified: {verified}")

    PasswordUtils.secure_zero(password)
    print(f"Password after deleting: {password}")
    print(f"Time cost: {time.time() - start:.2f} seconds")
