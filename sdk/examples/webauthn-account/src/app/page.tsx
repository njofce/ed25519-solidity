'use client';

import fetch from 'node-fetch';
import styles from './page.module.css'
import {
  getWebAuthnAttestation, 
  getWebAuthnAssertion, 
  getPublicKey, 
  generateRandomBuffer,
  parseSignature,
  PrecomputationBytecodeData,
  toBuffer,
  bytesToHex
} from '@tokensight/webauthn-sdk';


import WEB_AUTHN_ACCOUNT_FACTORY_DATA from './abis/WebAuthnAccountFactory.json';
import WEB_AUTHN_ACCOUNT_DATA from './abis/WebAuthnAccount.json';

import { createPublicClient, createWalletClient, encodeAbiParameters, encodePacked, keccak256, parseAbi } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { polygonMumbai } from 'viem/chains';
import { http } from 'viem';
import { getContract } from 'viem';
import { decodeEventLog } from 'viem';
import { useState } from 'react';

const pk = process.env.NEXT_PUBLIC_ACCOUNT_PK as `0x${string}`;
const account = privateKeyToAccount(pk)

/**
 * This example is running on Polygon Mumbai. It uses the Mumbai entrypoint for the smart contract accounts - 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789.
 */

export const walletClient = createWalletClient({
  chain: polygonMumbai,
  transport: http(process.env.NEXT_PUBLIC_RPC_URL),
  account
})

export const publicClient = createPublicClient({
  chain: polygonMumbai,
  transport: http(process.env.NEXT_PUBLIC_RPC_URL) 
})


export default function Home() {

  const [deployedWallet, setDeployedWallet] = useState('0x0' as `0x${string}`)
  
  const createWallet = async() => {
    const challenge = generateRandomBuffer(); // random init challenge
    const authenticatorUserId = generateRandomBuffer();

    const attestation = await getWebAuthnAttestation({
      publicKey: {
        authenticatorSelection: {
          residentKey: "preferred",
          requireResidentKey: false,
          userVerification: "preferred",
        },
        rp: {
          id: "localhost",
          name: "TokenSight Wallet Demo",
        },
        challenge,
        pubKeyCredParams: [{alg: -7, type: "public-key"}, {alg: -8, type: "public-key"}, {alg: -257, type: "public-key"}],
        user: {
          id: authenticatorUserId,
          name: "Wallet 7",
          displayName: "Wallet 7",
        },
      },
    })
   
    const credentialId: string = attestation.credentialId;

    // 1. Extract the public key
    const pubKey = await getPublicKey(attestation.attestationObject);
    
    console.log("Extracted public key");
    console.log(pubKey);
    console.log("Generating precomputations bytecode...");

    const xBn = BigInt(pubKey.x)
    const yBn = BigInt(pubKey.y)
    const xNum = xBn.toString(10);
    const yNum = yBn.toString(10);

    // 2. Generate precomputed tables
    const res = await fetch(`http://localhost:8081/precompute/${xNum}/${yNum}`)
    const precomputedTable: PrecomputationBytecodeData = await res.json();

    // 3. Create account onchain
    const encodedPublicKey = encodeAbiParameters(
      [
        { name: 'x', type: 'uint256' },
        { name: 'y', type: 'uint256' },
      ],
      [xBn, yBn]
    )

    console.log('encodedPublicKey', encodedPublicKey);
    console.log('credentialID', credentialId);
    console.log('bytecode', precomputedTable.bytecode);

    const contract = getContract({
      address: process.env.NEXT_PUBLIC_WEBAUTHN_ACCOUNT_FACTORY_ADDRESS as `0x${string}`,
      abi: WEB_AUTHN_ACCOUNT_FACTORY_DATA.abi,
      client: { public: publicClient, wallet: walletClient }
    })

    console.log("Deploying WebAuthnAccount...");

    // 4. Deploy wallet account for public key and credential ID
    const createdAccoutTxHash = await contract.write.createAccount([
      encodedPublicKey,
      credentialId,
      `0x${precomputedTable.bytecode}`
    ])

    const txReceipt = await publicClient.waitForTransactionReceipt({
      hash: createdAccoutTxHash,
      confirmations: 1
    })

    console.log(txReceipt.logs);
    const firstLog = txReceipt.logs[1];

    const decoded = decodeEventLog({
      abi: parseAbi(['event WebAuthnAccountInitialized(address indexed, address indexed)']),
      data: firstLog.data,
      topics: firstLog.topics
    });


    const contractAddress = decoded.args[0];
    const precomputationsAddress = decoded.args[1];
    
    console.log(`Deployed WebAuthn account to ${contractAddress}`);
    console.log(`Deployed WebAuthn precomputations to ${precomputationsAddress}`);
    setDeployedWallet(contractAddress);
  }

  const sendTransaction = async() => {
    const dw = "0x0F3796A1c708505A0E7CA59B8178f6cE1E743216";
    const contract = getContract({
      address: dw,
      abi: WEB_AUTHN_ACCOUNT_DATA.abi,
      client: { public: publicClient, wallet: walletClient }
    })

    // The account nonce should be used as the challenge, as it's always unique and can be used to verify signature on-chain.
    const nonce = await contract.read.getNonce();

    console.log(nonce);
    const nonceStr = (nonce as BigInt).toString();
    
    console.log("nonce:", (nonce as BigInt).toString(16));

    const credentialID = await contract.read.getCredentialId();
    console.log("credentialID", credentialID);

   const assertion = await getWebAuthnAssertion(nonceStr);
   console.log(assertion);

  // TODO: Move this logic to sdk
   const authData = assertion.authenticatorData;
   const clientDataJson = assertion.clientDataJson;

   const authDataBuffer: Uint8Array = toBuffer(authData);
   const clientDataBuffer: Uint8Array = toBuffer(clientDataJson);
  
  const authDataHex = bytesToHex(authDataBuffer);
  const clientDataHex = bytesToHex(clientDataBuffer);

  const clientDataChallengeOffset = 36;
  
  const encodedCallData = encodePacked(
    ['bytes', 'bytes', 'uint32'], 
    [`0x${authDataHex}`, `0x${clientDataHex}`, clientDataChallengeOffset]);

  console.log(encodedCallData)

    const signature = await parseSignature(assertion.signature);

    const encodedSignature = encodePacked(
      ['bytes', 'bytes'], 
      [
        `${signature.r}` as any,
        `${signature.s}` as any
      ]
    )

    /**
     * struct UserOperation {

        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        bytes paymasterAndData;
        bytes signature;
    }
     */

    console.log(dw);
    const encodedUserOp = encodePacked(
      ['address', 'uint256', 'bytes', 'bytes', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'bytes', 'bytes'], 
      [
        dw,
        nonce as any,
        '0x1',
        encodedCallData,
        BigInt(1),
        BigInt(1),
        BigInt(1),
        BigInt(1),
        BigInt(1),
        '0x1',
        encodedSignature
      ]
    )
  
    console.log(encodedUserOp);

    const res = await contract.write.validateUserOp([encodedUserOp, keccak256(encodedUserOp), '0x0']);
    console.log(res);

    // const options = {
    //   method: 'POST',
    //   headers: {accept: 'application/json', 'content-type': 'application/json'},
    //   body: JSON.stringify({
    //     id: 1,
    //     jsonrpc: '2.0',
    //     method: 'eth_sendUserOperation',
    //     params: [
    //       {
    //         sender: dw,
    //         nonce: `0x${(nonce as BigInt).toString(16)}`,
    //         initCode: '0x',
    //         callData: encodedCallData,
    //         callGasLimit: '0x7A1200',
    //         verificationGasLimit: '0x927C0',
    //         preVerificationGas: '0x15F90',
    //         maxFeePerGas: '0x656703D00',
    //         maxPriorityFeePerGas: '0x13AB6680',
    //         signature: encodedSignature,
    //         paymasterAndData: '0x'
    //       },
    //       '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789'
    //     ]
    //   })
    // };
    
    // fetch(process.env.NEXT_PUBLIC_RPC_URL as string, options)
    //   .then(response => response.json())
    //   .then(response => console.log(response))
    //   .catch(err => console.error(err));
  }

  return (
    <main className={styles.main}>
      <div className={styles.description}>
        <p>
          Get started by creating a WebAuthn wallet.
        </p>

        <div onClick={() => createWallet()}>
          Create
        </div>

        <div onClick={() => sendTransaction()}>
          Sign Transaction
        </div>
      </div>

    </main>
  )
}
