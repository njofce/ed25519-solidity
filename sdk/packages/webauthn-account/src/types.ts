export type ExternalAuthenticatorTransports = AuthenticatorTransport | "hybrid";

export type InternalAuthenticatorTransports = "AUTHENTICATOR_TRANSPORT_BLE"
| "AUTHENTICATOR_TRANSPORT_INTERNAL"
| "AUTHENTICATOR_TRANSPORT_NFC"
| "AUTHENTICATOR_TRANSPORT_USB"
| "AUTHENTICATOR_TRANSPORT_HYBRID";

export type PublicKeyCredentialRequestConfig = {
    challenge: string;
    timeout?: number;
    rpId?: string;
    allowCredentials?: PublicKeyCredentialDescriptor[];
    userVerification?: UserVerificationRequirement;
    extensions?: AuthenticationExtensionsClientInputs;
};
  
export type CredentialRequestConfig = {
    mediation?: CredentialMediationRequirement;
    publicKey: PublicKeyCredentialRequestConfig;
    signal?: AbortSignal;
    password?: boolean;
    unmediated?: boolean;
};

export type PublicKey = {
    x: string;
    y: string;
}

export type Signature = {
    r: string;
    s: string;
}

export type WebAuthnSignaturePayload = {

    /** Base64 encoded unique id for a credential. */
    credentialId: string;
    
    /** Base64 encoded payload with signing context and challenge. */
    clientDataJson: string;
    
    /** Base64 encoded payload with metadata about the authenticator used to generate signature. */
    authenticatorData: string;
    
    /** Base64 encoded signature bytes from the WebAuthn assertion response. */
    signature: string;
}

export type WebAuthnAttestation = {

     /** base64(cbor(credentialID)) */
     credentialId: string;

     /** Base64 encoded payload with signing context and challenge. */
     clientDataJson: string;

     /** Base64 encoded payload with authenticator data and any attestation chosen by the webauthn provider */
     attestationObject: string;

     /** The type of chosen authenticator transports. */
     transports: InternalAuthenticatorTransports [];
}

export enum COSEKEYS {
    kty = 1,
    alg = 3,
    crv = -1,
    x = -2,
    y = -3,
    n = -1,
    e = -2,
}