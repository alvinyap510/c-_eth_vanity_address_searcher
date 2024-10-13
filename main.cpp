#include <iostream>
#include <vector>
#include <string>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <secp256k1.h>
#include <iomanip>
#include <sstream>
#include <tuple>

// Function to convert mnemonic to seed
std::vector<unsigned char>
mnemonicToSeed(const std::string &mnemonic, const std::string &passphrase = "")
{
    const std::string salt = "mnemonic" + passphrase;
    std::vector<unsigned char> seed(64);

    PKCS5_PBKDF2_HMAC(mnemonic.c_str(), mnemonic.size(),
                      reinterpret_cast<const unsigned char *>(salt.c_str()), salt.size(),
                      2048, EVP_sha512(), 64, seed.data());

    return seed;
}

// HMAC-SHA512 function
std::vector<unsigned char> hmacSha512(const std::vector<unsigned char> &key, const std::vector<unsigned char> &data)
{
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    HMAC(EVP_sha512(), key.data(), key.size(), data.data(), data.size(), hash, &lengthOfHash);

    return std::vector<unsigned char>(hash, hash + lengthOfHash);
}

std::tuple<std::vector<unsigned char>, std::vector<unsigned char>, std::vector<unsigned char>> deriveChildKey(
    const std::vector<unsigned char> &parentKey,
    const std::vector<unsigned char> &chainCode,
    uint32_t index)
{
    std::vector<unsigned char> data;
    if (index >= 0x80000000)
    {
        data.push_back(0x00);
        data.insert(data.end(), parentKey.begin(), parentKey.end());
    }
    else
    {
        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        secp256k1_pubkey pubkey;
        if (secp256k1_ec_pubkey_create(ctx, &pubkey, parentKey.data()) != 1)
        {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to create public key");
        }
        unsigned char serializedPubkey[33];
        size_t len = sizeof(serializedPubkey);
        secp256k1_ec_pubkey_serialize(ctx, serializedPubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED);
        secp256k1_context_destroy(ctx);
        data.insert(data.end(), serializedPubkey, serializedPubkey + 33);
    }
    data.push_back((index >> 24) & 0xFF);
    data.push_back((index >> 16) & 0xFF);
    data.push_back((index >> 8) & 0xFF);
    data.push_back(index & 0xFF);

    std::vector<unsigned char> output = hmacSha512(chainCode, data);
    std::vector<unsigned char> childKey(32), childChainCode(32);

    std::copy(output.begin(), output.begin() + 32, childKey.begin());
    std::copy(output.begin() + 32, output.end(), childChainCode.begin());

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (secp256k1_ec_seckey_tweak_add(ctx, childKey.data(), parentKey.data()) != 1)
    {
        secp256k1_context_destroy(ctx);
        throw std::runtime_error("Child key derivation failed");
    }

    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_create(ctx, &pubkey, childKey.data()) != 1)
    {
        secp256k1_context_destroy(ctx);
        throw std::runtime_error("Failed to create public key");
    }
    unsigned char publicKey[33];
    size_t pubkeyLen = sizeof(publicKey);
    secp256k1_ec_pubkey_serialize(ctx, publicKey, &pubkeyLen, &pubkey, SECP256K1_EC_COMPRESSED);
    secp256k1_context_destroy(ctx);

    return {childKey, childChainCode, std::vector<unsigned char>(publicKey, publicKey + pubkeyLen)};
}

// Keccak-256 hash function (using OpenSSL's SHA3-256, which is equivalent for this purpose)
std::vector<unsigned char> keccak256(const std::vector<unsigned char> &input)
{
    std::vector<unsigned char> hash(32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_MD *md = EVP_MD_fetch(NULL, "KECCAK-256", NULL);

    if (md == NULL)
    {
        throw std::runtime_error("Failed to fetch KECCAK-256");
    }

    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, input.data(), input.size());
    unsigned int hashLen;
    EVP_DigestFinal_ex(ctx, hash.data(), &hashLen);

    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);

    return hash;
}

std::string toChecksumAddress(const std::string &address)
{
    std::string addressLower = address.substr(2); // Remove "0x"
    std::vector<unsigned char> addressBytes(addressLower.begin(), addressLower.end());
    std::vector<unsigned char> addressHash = keccak256(addressBytes);

    std::string result = "0x";
    for (size_t i = 0; i < addressLower.length(); i++)
    {
        if (addressLower[i] >= '0' && addressLower[i] <= '9')
        {
            result += addressLower[i];
        }
        else
        {
            result += (addressHash[i / 2] & (i % 2 ? 0x0f : 0xf0)) >= 0x80 ? toupper(addressLower[i]) : addressLower[i];
        }
    }
    return result;
}

std::string generateEthereumAddress(const std::vector<unsigned char> &compressedPublicKey)
{
    // Decompress the public key
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, compressedPublicKey.data(), compressedPublicKey.size()))
    {
        secp256k1_context_destroy(ctx);
        throw std::runtime_error("Failed to parse public key");
    }

    // Serialize to uncompressed format
    unsigned char uncompressedPubkey[65];
    size_t outputLen = 65;
    secp256k1_ec_pubkey_serialize(ctx, uncompressedPubkey, &outputLen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_context_destroy(ctx);

    // Remove the first byte (0x04) which indicates uncompressed key
    std::vector<unsigned char> keyWithoutPrefix(uncompressedPubkey + 1, uncompressedPubkey + 65);

    // Hash the public key
    std::vector<unsigned char> hash = keccak256(keyWithoutPrefix);

    // Take the last 20 bytes of the hash
    std::stringstream ss;
    ss << "0x";
    for (int i = 12; i < 32; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return toChecksumAddress(ss.str());
}

// Helper function to convert bytes to hex string
std::string bytesToHexString(const std::vector<unsigned char> &bytes)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto &byte : bytes)
    {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

// New function to get the derived path
std::string getDerivedPath(uint32_t account, uint32_t change, uint32_t index)
{
    std::stringstream ss;
    ss << "m/44'/60'/" << account << "'/" << change << "/" << index;
    return ss.str();
}

// Function to derive master key and chain code from seed
std::pair<std::vector<unsigned char>, std::vector<unsigned char>> deriveMasterKeyFromSeed(const std::vector<unsigned char> &seed)
{
    std::vector<unsigned char> hmacKey(12, 0);
    std::copy(std::begin("Bitcoin seed"), std::end("Bitcoin seed") - 1, hmacKey.begin());

    std::vector<unsigned char> hmacResult = hmacSha512(hmacKey, seed);

    std::vector<unsigned char> masterKey(hmacResult.begin(), hmacResult.begin() + 32);
    std::vector<unsigned char> chainCode(hmacResult.begin() + 32, hmacResult.end());

    return {masterKey, chainCode};
}

int main()
{
    // Sample mnemonic phrase, insert your own
    std::string mnemonic = "able route prevent blood few lumber company convince discover slight menu good child gadget brother truck farm buyer paddle extend object click cradle hero";
    std::string passphrase = ""; // Optional passphrase

    // Generate derived path - customize derived path so that even people get your mnemonic phrase, they
    // would never know your derived path to gegerate the correct address.
    // Derived Path Format ```m/44'/60'/{account}'/{change}/{starting_address_index}```
    uint32_t account = 10;
    uint32_t change = 12;
    uint32_t starting_address_index = 4294917290;
    std::string prefix_search = "0x0000";

    std::vector<unsigned char> seed = mnemonicToSeed(mnemonic, passphrase);
    std::cout << "Seed: " << bytesToHexString(seed) << std::endl;

    auto [masterKey, chainCode] = deriveMasterKeyFromSeed(seed);
    std::cout << "Master Key: " << bytesToHexString(masterKey) << std::endl;
    std::cout << "Chain Code: " << bytesToHexString(chainCode) << std::endl;

    // Derive m/44'/60'/{account}'
    auto derived = deriveChildKey(masterKey, chainCode, 0x80000000 + 44);
    derived = deriveChildKey(std::get<0>(derived), std::get<1>(derived), 0x80000000 + 60);
    derived = deriveChildKey(std::get<0>(derived), std::get<1>(derived), 0x80000000 + account);

    while (true)
    {
        // Derive m/44'/60'/{account}'/{change}
        auto changeKey = deriveChildKey(std::get<0>(derived), std::get<1>(derived), change);

        while (true)
        {
            auto addressKey = deriveChildKey(std::get<0>(changeKey), std::get<1>(changeKey), starting_address_index);

            std::string address = generateEthereumAddress(std::get<2>(addressKey));

            if (address.substr(0, prefix_search.length()) == prefix_search)
            {
                std::string derivedPath = getDerivedPath(account, change, starting_address_index);
                std::cout << "Found matching address: " << address << std::endl;
                std::cout << "Private Key: " << bytesToHexString(std::get<0>(addressKey)) << std::endl;
                std::cout << "Public Key: " << bytesToHexString(std::get<2>(addressKey)) << std::endl;
                std::cout << "Derived Path: " << derivedPath << std::endl;
                std::cout << "at change: " << change << ", index: " << starting_address_index << std::endl;
                return 0; // Exit the program after finding a match
            }

            if (starting_address_index == UINT32_MAX)
            {
                break; // Break the inner loop to increment change
            }

            starting_address_index++;

            if (starting_address_index % 1000 == 0)
            {
                std::cout << "Checked addresses at change " << change
                          << ", index " << starting_address_index << std::endl;
            }
        }

        change++;
        starting_address_index = 0;
        std::cout << "Reached max index. Incrementing change to " << change
                  << " and resetting index to 0" << std::endl;
    }

    return 0;
}

// g++-14 -std=c++17 -I/opt/homebrew/opt/openssl@3/include -I/opt/homebrew/opt/secp256k1/include -I/opt/homebrew/opt/cryptopp/include -L/opt/homebrew/opt/openssl@3/lib -L/opt/homebrew/opt/secp256k1/lib -L/opt/homebrew/opt/cryptopp/lib -lssl -lcrypto -lsecp256k1 -lcryptopp main.cpp -o eth_vanity_address_searcher