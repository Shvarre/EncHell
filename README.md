# Diffie-Hellman Key Exchange and AES Encryption Demo



## Description

This project is a demonstration of the Diffie-Hellman Key Exchange algorithm and AES Encryption/Decryption process. It includes a user interface created with `tkinter` for interactive engagement. Users can experiment with generating shared keys using the Diffie-Hellman method and then use these keys for AES encryption and decryption of messages.



## Features

- Interactive GUI for generating shared keys using Diffie-Hellman Key Exchange.

- AES Encryption and Decryption of text messages.

- Generation and use of Initialization Vectors (IV) and salt for AES encryption.

- Error handling for encryption and decryption processes.

## GUI Overview

Diffie-Hellman Key Exchange Section: Allows users to enter private numbers for Alice and Bob, select a prime number, and compute public and shared keys.

AES Encryption/Decryption Section: Users can input a shared key, generate IV, input text for encryption or decryption, and view the output.

## Note

This project is intended for educational purposes and should not be used for securing sensitive data in a production environment.

## Dependencies

To run this project, the following libraries need to be installed:



- `tkinter` - for the GUI.

- `pycryptodome` - for cryptographic operations including AES and SHA256 hashing.



You can install `pycryptodome` using pip:



```bash

pip install pycryptodome

How to Run

    Ensure Python 3.x is installed on your system.

    Install the pycryptodome package.

    Clone the repository or download the script file.

    Run the script:

    bash

    python path/to/script.py

