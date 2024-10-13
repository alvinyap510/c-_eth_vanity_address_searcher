# ETH-Vanity-Address-Searcher

This project is the implementation of ethereum vanity addresses searching in C++.

Example of vanity addresses: "0x000000...", "0xffffff...", "0xc0ff33...", "0xd3ad..." etc

## Prerequisites

- Make sure you have `secp256k1` and `openssl` installed in your system

## Configure

- Update your mnemonic phrase in the `main.cpp` file, and choose your starting derived path
- The derived path follows this format `Derived Path Format m/44'/60'/{account}'/{change}/{starting_address_index}`

## Compile and Run

Compile

MacOS:

```shell
g++ -std=c++17 -I/opt/homebrew/opt/openssl@3/include -I/opt/homebrew/opt/secp256k1/include -L/opt/homebrew/opt/openssl@3/lib -L/opt/homebrew/opt/secp256k1/lib -lssl -lcrypto -lsecp256k1 main.cpp -o eth_vanity_address_searcher
```

Should the include and lib directory does not match in your machine, you can run below command to search for the installled directory:

```shell
brew --prefix <package_name>
```

Run

```shell
./eth_vanity_address_searcher
```

## Benchmark Approximation

This codebase's vanity address search is approximately 5-7x faster than the implementation of [Vanity-Eth](https://github.com/MyEtherWallet/VanityEth) / [Vanity-Eth Web Version](https://vanity-eth.tk/), since the latter's implemenation is in JavaScript.

However, this codebase's is still much less efficient than Profanity's [implementation](https://github.com/johguse/profanity), since Profanity utilizes GPU in its computation. NOTE: Profanity's seed generatation is partially predictable, so avoid using Profanity at its current state.

## Future Improvements

Planned improvements for this project include:

- GPU utilization for faster address generation and search.
- Multi-threading to parallelize search tasks across multiple CPU cores.
- Advanced pattern matching to allow for more complex vanity address searches.
