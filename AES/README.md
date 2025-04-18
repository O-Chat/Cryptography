# AES Encryption and Decryption (128-bit) - C++ Implementation

This project provides a command-line utility to perform AES-128 encryption and decryption using a class-based implementation in C++.

---

📁 Files in This Folder

- `AES.h` – Header file with AES class declaration and function prototypes
- `AES.cpp` – Source file with function definitions for AES operations
- `MAIN.cpp` – Main program to perform encryption and decryption using command-line inputs
- `input.txt` – Sample plaintext file for testing

---

🔐 Features

- AES-128 bit encryption and decryption
- ECB mode of operation
- Automatically generates the AES key internally
- File-based encryption and decryption (input and output)



🛠️ COMPILE
Use `g++` to compile all the files:
bash
```g++ -o aes_program MAIN.cpp AES.cpp ```

USAGE
```./aes_program <encrypt|decrypt> <input file> <output file>```

ENCRYPT
```./aes_program encrypt input.txt encrypted.txt```
This will read plaintext from input.txt, encrypt it, and save the result in encrypted.txt.

DECRYPT
```./aes_program decrypt encrypted.txt decrypt.txt```
This will read ciphertext from encrypted.txt, decrypt it using the same key (generated internally), and save the result in decrypt.txt.

SAMPLE input.txt
Hello, this is a test file for AES encryption.
This line is also part of the plaintext input.

OUTPUT
encrypted.txt will contain encrypted binary data
decrypt.txt will reproduce the original message from input.txt after decryption

NOTES
    This implementation uses a fixed internally generated key for both encryption and decryption.
    Key and state management are done inside the AES class.
    File I/O is handled in the MAIN.cpp file.

Happy Encrypting! 🔐


