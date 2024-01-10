export { 
    PublicKeyCredentialRequestConfig, 
    CredentialRequestConfig, 
    WebAuthnAttestation, 
    WebAuthnSignaturePayload, 
    PublicKey,
    Signature,
    PrecomputationBytecodeData,
    WebAuthnAuthSignatureData
} from './types';

export { 
    hasWebAuthnSupport, 
    generateRandomBuffer, 
    base64UrlEncode, 
    toBuffer,
    bytesToHex
} from './utils';

export { 
    getWebAuthnAttestation, 
    getWebAuthnAssertion, 
    getPublicKey, 
    parseSignature, 
    getMessageHash,
    getAssertionHexData
} from './core';