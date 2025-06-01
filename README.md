Secure Password Utilities

A Python class for secure password management: generating strong passwords, hashing them with Argon2, and safely verifying them.

   Features
Secure Password Generation: Creates strong, random passwords using Python's secrets module, ensuring a mix of character types and avoiding simple repetitions.

Argon2 Hashing: Uses the recommended Argon2 algorithm via pyargon2 for robust password hashing. Configurable for time, memory, and parallelism to balance security and performance.

Timing Attack Protection: Employs constant-time comparison (secrets.compare_digest) during verification to prevent attackers from guessing passwords based on timing differences.

Memory Zeroing: Includes a secure_zero function to overwrite raw password data (bytearray) in memory immediately after use, reducing the risk of data leakage.

   Installation
Install pyargon2 via pip:

   Bash

pip install pyargon2
   Usage Example
	 
	Python

	import time
	from password_utils import PasswordUtils

	if __name__ == "__main__":
   	 print("--- Password Management Demo ---")

    # 1. Generate a secure password (as bytearray)
    raw_password = PasswordUtils.generate(length=16) 
    print(f"Generated password: {raw_password.decode('utf-8')}")

    # 2. Hash the password (returns hashed_password_bytes, salt_bytes)
    hashed_password, salt = PasswordUtils.hash_password(raw_password)
    print(f"Hashed password: {hashed_password}")
    print(f"Salt: {salt}")

    # 3. Verify the password
    is_verified = PasswordUtils.verify_hash(raw_password, salt, hashed_password)
    print(f"Password verified: {is_verified}")

    # 4. Securely wipe the raw password from memory
    PasswordUtils.secure_zero(raw_password)
    print(f"Password after zeroing: {raw_password}")

    print(f"Demo complete in {time.time() - start_time:.2f} seconds.")
		
🔒 Security Notes

Argon2 Parameters: Adjust time_cost, memory_cost, and parallelism for your specific needs; higher values mean more security but use more resources.

Zeroing Raw Passwords: Always use PasswordUtils.secure_zero() on bytearray objects containing raw passwords immediately after use.

Storing Hashes/Salts: Store hashed_password and salt securely in your database. They are bytes objects and cannot be explicitly zeroed from memory like bytearray.

   Contributing
	 
Contributions, bug reports, and suggestions are welcome! Feel free to open an Issue or submit a Pull Request.
