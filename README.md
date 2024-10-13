# ETH-Vanity-Address-Searcher

This project is the implementation of ethereum vanity addresses searching in C++.

Example of vanity addresses: "0x000000...", "0xffffff...", "0xc0ff33...", "0xd3ad..." etc

## Before Running

- Make sure you have `secp256k1` and `openssl` installed in your system

## Configure

- Update your mnemonic phrase in the `main.cpp` file, and choose your starting derived path
- The derived path follows this format `Derived Path Format m/44'/60'/{account}'/{change}/{starting_address_index}`

## Compile and Run

Compile

```shell
g++ -std=c++17 -I/opt/homebrew/opt/openssl@3/include -I/opt/homebrew/opt/secp256k1/include -L/opt/homebrew/opt/openssl@3/lib -L/opt/homebrew/opt/secp256k1/lib -lssl -lcrypto -lsecp256k1 main.cpp -o eth_vanity_address_searcher
```

Run

```shell
./eth_vanity_address_searcher
```
