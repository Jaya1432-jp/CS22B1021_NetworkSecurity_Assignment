 DES (Data Encryption Standard) Algorithm Implementation

## Overview

This repository contains a C implementation of the Data Encryption Standard (DES) algorithm, as outlined in FIPS PUB 46-3. DES is a symmetric-key block cipher that encrypts or decrypts 64-bit blocks of data using a 56-bit key, following a series of transformations and substitutions to ensure data security.

## Features

- **Encryption and Decryption**: The implementation supports both encryption and decryption using the DES algorithm.
- **Key Scheduling**: The algorithm generates 16 subkeys from the original key using permutation and shifting operations.
- **S-Box Substitution**: Uses 8 distinct S-boxes to substitute bits in each round of encryption.
- **Initial and Final Permutations**: Implements the initial and final permutations (IP and PI) required in the DES algorithm.

## Key Operations

- **Initial Permutation (IP)**: Reorganizes the input data.
- **Round Function**: Expands, substitutes, and permutes data at each round using round keys.
- **Key Schedule**: Generates round keys using Permuted Choice 1 (PC1) and Permuted Choice 2 (PC2).
- **Final Permutation (PI)**: Applies the inverse of the initial permutation to the result of the final round.

## How It Works

1. **Input and Key**: 
   - 64-bit data is taken as input.
   - 64-bit key is used for encryption/decryption, though only 56 bits are used.

2. **Initial Permutation**: The input data undergoes an initial permutation (IP).

3. **Rounds**: 16 rounds of encryption/decryption occur, using round keys derived from the original key.

4. **Final Permutation**: The result of the final round undergoes the inverse initial permutation (PI) to produce the output.

## Example

The following test case demonstrates encryption and decryption:

- **Input (X0)**: `9474B8E8C73BCA7D`
- **Final Output (X16)**: `1B1A2DDB4C642438`
