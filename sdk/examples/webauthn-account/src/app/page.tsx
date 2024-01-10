'use client';

import fetch from 'node-fetch';
import styles from './page.module.css'
import {
  getWebAuthnAttestation, 
  getWebAuthnAssertion, 
  getAssertionHexData,
  getPublicKey, 
  generateRandomBuffer,
  parseSignature,
  PrecomputationBytecodeData,
} from '@tokensight/webauthn-sdk';

import WEB_AUTHN_ACCOUNT_FACTORY_DATA from './abis/WebAuthnAccountFactory.json';
import WEB_AUTHN_ACCOUNT_DATA from './abis/WebAuthnAccount.json';

import { createPublicClient, createWalletClient, encodeAbiParameters, encodePacked, keccak256, parseAbi, parseAbiParameters } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { polygonMumbai } from 'viem/chains';
import { http } from 'viem';
import { getContract } from 'viem';
import { decodeEventLog } from 'viem';
import { useState } from 'react';
import assert from 'assert';

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
          name: "Wallet 8",
          displayName: "Wallet 8",
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
    const dw = "0x5251f340adc879cb71a88dcf4ec1629c659f9f00"; // Should be retrieved from state.
    const contract = getContract({
      address: dw,
      abi: WEB_AUTHN_ACCOUNT_DATA.abi,
      client: { public: publicClient, wallet: walletClient }
    })

    // The account nonce should be used as the challenge, as it's always unique and can be used to verify signature on-chain.
    const nonce = (await contract.read.getNonce() as BigInt);
    const nonceStr = nonce.toString();
    
    const assertion = await getWebAuthnAssertion(nonceStr);
    const assertionData = await getAssertionHexData(assertion)
    
    const encodedCallData = encodeAbiParameters(
      parseAbiParameters('bytes x, bytes y, uint32 z'),
      [`0x${assertionData.authDataHex}`, `0x${assertionData.clientDataHex}`, assertionData.clientDataChallengeOffset]
    );

    const signature = await parseSignature(assertion.signature);

    const encodedSignature = encodePacked(
      ['bytes', 'bytes'], 
      [
        `${signature.r}` as any,
        `${signature.s}` as any
      ]
    )

    const userOpData = [
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
    ];
    const encodedUserOp = encodePacked(
      ['address', 'uint256', 'bytes', 'bytes', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'bytes', 'bytes'], 
      userOpData as any
    )

    const { result } = await publicClient.simulateContract({
      address: dw,
      abi: WEB_AUTHN_ACCOUNT_DATA.abi,
      functionName: 'validateUserOp',
      args: [
        userOpData, 
        keccak256(encodedUserOp), 
        1
      ],
      account: '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789' // simulate call from entry point
    })
  
    assert((result as BigInt).toString() == '0', 'Invalid signature');
    console.log("UserOp simulated successfully");
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
