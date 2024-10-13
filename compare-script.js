const ethers = require("ethers");
const crypto = require("crypto");

function generateEthereumKeys(mnemonic) {
  try {
    // 1. Generate Seed
    const seed = ethers.utils.mnemonicToSeed(mnemonic);

    // 2. Generate Master Key
    const masterKey = crypto
      .createHmac("sha512", "Bitcoin seed")
      .update(seed)
      .digest();

    // Create HDNode from seed
    const hdNode = ethers.utils.HDNode.fromSeed(seed);

    // 3. Derive Chain Node (using Ethereum's path m/44'/60'/0'/0/0)
    const chainNode = hdNode.derivePath("m/44'/60'/0'/0/0");

    // 4. Final Private Key
    const privateKey = chainNode.privateKey;

    // 5. Public Key
    const publicKey = ethers.utils.computePublicKey(privateKey, true); // true for compressed format

    // 6. Generated Address
    const wallet = new ethers.Wallet(privateKey);
    const address = wallet.address;

    return {
      seed: seed.toString("hex"),
      masterKey: masterKey.toString("hex"),
      chainNode: chainNode.publicKey,
      privateKey: privateKey,
      publicKey: publicKey,
      address: address,
    };
  } catch (error) {
    throw new Error("Error generating Ethereum keys: " + error.message);
  }
}

// Example usage
const mnemonic =
  "loan candy culture mixture olympic original order trial earn ask anxiety when vintage garlic alert once fee vacuum crouch dose cable yard rude sail";
try {
  const keys = generateEthereumKeys(mnemonic);
  console.log("1. Seed:", keys.seed);
  console.log("2. Master Key:", keys.masterKey);
  console.log("3. Chain Node:", keys.chainNode);
  console.log("4. Private Key:", keys.privateKey);
  console.log("5. Public Key:", keys.publicKey);
  console.log("6. Address:", keys.address);
} catch (error) {
  console.error("Error:", error.message);
}
