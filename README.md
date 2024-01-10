# ERC4337 Accounts with on-chain sec256r1 signature verificaiton

This repository contains the primitives for defining and deploying ERC-4337 accounts using on-chain sec256r1 signature verification. It uses a gas-efficient approach as proposed in (FCL)[https://github.com/rdubois-crypto/FreshCryptoLib].

We are providing the following primitives:
1. A Precomputations server written in Rust
2. A WebAuthnAccount ERC4337 smart contract that validates a sec256r1 signature on-chain as part of the userOp validation phase.
3. A WebAuthnAccountFactory smart contract that deterministally deploys an account contract for a given credential and public key.
4. An abstract MFAAccount smart contract which can be used in creating and deploying MFA accounts, where the second signature authentication factor is a sec256r1 signature.
5. A simple Typescript SDK for interacting with WebAuthn standard on the client side and generating all the necessary
6. An example app written in Next.js that deploys a WebAuthnAccount on-chain and simulates a userOp with a valid signature.

## Running the example application

1. Start the Precomputations server

It is recommended to run the precomputations server using Docker to avoid installing SageMath locally in your machine. Follow
the Readme in the `precomputations_server` to understand more about how it works and how to run it.

2. Build the local SDK

```
    cd sdk/
    pnpm i
    pnpm run build-all
```

3. Run the example application (make sure to populate the .env file with the right parameters)

```
    cd examples/webauthn-account
    npm run dev
```

The example will allow you to create a webauthn wallet, which will deploy the wallet on-chain, and sign a transaction with that wallet. 

You can use the code in the example in your apps to deploy WebAuthnAccount wallets as well as sign transactions using those.

## MFA smart accounts

This repo contains a simple example for MFAAccount smart contract, which provides the foundation for validating sec256r1 signature on-chain using a precomputed table for public key parameters, as well as managing the devices. However, any project can provide a different implementation for this and doesn't necessarily need to follow any guidelines, but only use the provided primitives from our repo as a starting point.

We intend to build this as a validator in zerodev smart contract accounts: [ZeroDev Validator](https://github.com/zerodevapp/kernel/tree/main/src/validator)
