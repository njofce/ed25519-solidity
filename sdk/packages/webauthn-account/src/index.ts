export { 
    PublicKeyCredentialRequestConfig, 
    CredentialRequestConfig, 
    WebAuthnAttestation, 
    WebAuthnSignaturePayload, 
    PublicKey,
    Signature,
    PrecomputationBytecodeData
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
    getMessageHash 
} from './core';