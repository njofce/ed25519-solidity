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

import { createPublicClient, createWalletClient, custom, encodeAbiParameters, parseAbi, toHex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { polygonMumbai, sepolia } from 'viem/chains'
import { http } from 'viem'
import { getContract } from 'viem'
import { keccak256 } from 'viem'
import { decodeEventLog } from 'viem'

export const account = privateKeyToAccount(process.env.NEXT_PUBLIC_ACCOUNT_PK as `0x${string}`)

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
          name: "Wallet 5",
          displayName: "Wallet 5",
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


    // WebAuthnAccount('')
  }

  const sign = async() => {
    const contract = getContract({
      address: '0x8809242Ebdf3B408B9A56dA6D0089c441C25F079',
      abi: WEB_AUTHN_ACCOUNT_DATA.abi,
      client: { public: publicClient, wallet: walletClient }
    })

    const nonce = await contract.read.getNonce();
    const nonceStr = (nonce as BigInt).toString();
    
    console.log(nonceStr);

    const credentialID = await contract.read.getCredentialId();
    console.log(credentialID);

   const assertion = await getWebAuthnAssertion(nonceStr);
   console.log(assertion);

   const authData = assertion.authenticatorData;
   const clientDataJson = assertion.clientDataJson;

   const authDataBuffer: Uint8Array = toBuffer(authData);
   const clientDataBuffer: Uint8Array = toBuffer(clientDataJson);
  
  const authDataHex = bytesToHex(authDataBuffer);
  const clientDataHex = bytesToHex(clientDataBuffer);

  console.log(authDataHex);
  console.log(clientDataHex);

  const signature = await parseSignature(assertion.signature);
  console.log(signature);

   // TODO: Send a transaction
  }

  return (
    <main className={styles.main}>
      <div className={styles.description}>
        <p>
          Get started by creating a WebAuthn wallet.
        </p>

        <div
          onClick={() => createWallet()}
        >
          Create
        </div>

        <div
          onClick={() => sign()}
        >
          Sign Transaction
        </div>
      </div>

    </main>
  )
}
