# DES-Data-Encryption-Standard
DES ALGORITHM PROCEDURE:
INITIAL PERMUTATION (IP):
At the outset, a 64-bit plaintext message undergoes an initial permutation.
This permutation rearranges the bits in the message to create an altered input.
ROUND FUNCTION (16 ROUNDS):
The heart of DES lies in its round function, which is repeated 16 times.
In each round, a 32-bit input (half of the initial 64-bit block) is expanded to 48 bits using an expansion          permutation.
This expanded output is XORed with a round-specific 48-bit subkey derived from the original 56-bit encryption key.
The result of this XOR operation is then subjected to S-box substitutions, where 48 bits are reduced to 32 bits through a predefined substitution process.
After S-box substitution, a fixed permutation (straight P-box) is applied to further modify the data.
The output of the straight P-box becomes the input for the next round.
FINAL SWAP:
Following 16 rounds, the halves of the data block are swapped, with the left half becoming the new right half and vice versa.
INVERSE INITIAL PERMUTATION (IP^-1) OR FINAL PERMUTATION (FP):
The final swapped 64-bit data block is subjected to an inverse initial permutation.
This permutation undoes the initial rearrangement and produces the 64-bit ciphertext.
CIPHERTEXT:
The 64-bit ciphertext is the output of the DES encryption process.

KEY GENERATION:
INITIAL KEY PROCESSING:
A 64-bit encryption key is provided, but only 56 bits are used for actual encryption.
The initial key undergoes a process called the parity drop table, resulting in a 56-bit key.
KEY SPLITTING AND CIRCULAR SHIFTS:
The 56-bit key is divided into two 28-bit halves, resembling a Feistel structure.
Each half is subjected to individual left circular shifts.
The results of the circular shifts are combined to create a new 56-bit key.
ROUND-SPECIFIC KEY GENERATION:
The new 56-bit key is further compressed using a compression permutation (compression D-box) to generate a unique 48-bit subkey for each round of encryption.


OUTPUT:

![des_example1](https://github.com/Neeraja-Kallamadi/DES-Data-Encryption-Standard-/assets/110168775/729c3ea2-be09-47a7-a4da-9883f6f29cdd)

![des_example2](https://github.com/Neeraja-Kallamadi/DES-Data-Encryption-Standard-/assets/110168775/94e9cfb0-e5cd-438d-b934-541b5c998da7)

![DES Output](https://github.com/Neeraja-Kallamadi/DES-Data-Encryption-Standard-/assets/110168775/854d3396-e220-4aaa-a9f1-1724b36fc4bb)
