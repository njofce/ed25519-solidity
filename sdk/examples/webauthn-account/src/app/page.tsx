'use client';

import styles from './page.module.css'
import {
  getWebAuthnAttestation, 
  getWebAuthnAssertion, 
  getPublicKey, 
  generateRandomBuffer,
  parseSignature
} from '@tokensight/webauthn-sdk';


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
          name: "Wallet 2",
          displayName: "Wallet 2",
        },
      },
    })
    
   
    const credentialId = attestation.credentialId;
    const pubKey = await getPublicKey(attestation.attestationObject);
    
    console.log(pubKey);
    // TODO: Deploy wallet for public key and credential ID
  }

  const sign = async() => {
   const assertion = await getWebAuthnAssertion("Random challenge");
   console.log(assertion);

   const signature = await parseSignature(assertion.signature);
   console.log(signature);

   // TODO: Send transaction
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
