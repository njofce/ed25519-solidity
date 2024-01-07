import cbor from 'cbor';
import elliptic from "elliptic";

import { COSEKEYS, CredentialRequestConfig, ExternalAuthenticatorTransports, InternalAuthenticatorTransports, PublicKey, Signature, WebAuthnAttestation, WebAuthnSignaturePayload } from "./types";
import { concat, hasWebAuthnSupport, shouldRemoveLeadingZero, toBuffer, toHash } from "./utils";
import type { PublicKeyCredentialWithAttestationJSON } from "./webauthn-json";
import {
  get as webauthnCredentialGet,
  create as webauthnCredentialCreate,
} from "./webauthn-json";

import { ECDSASigValue } from "@peculiar/asn1-ecc";
import { AsnParser } from "@peculiar/asn1-schema";

const EC = elliptic.ec;
const ec = new EC("p256");

export const DEFAULT_TIMEOUT = 1 * 60 * 1000; // one minute timeout
export const DEFAULT_USER_VERIFICATION = "preferred";

export async function getWebAuthnAttestation(
    options: CredentialCreationOptions
  ): Promise<WebAuthnAttestation> {
    const webAuthnSupported = hasWebAuthnSupport();
  
    if (!webAuthnSupported) {
      throw new Error("webauthn is not supported by this browser");
    }
  
    const res = await webauthnCredentialCreate(options);
  
    return toInternalAttestation(res.toJSON());
}

export async function getPublicKey(attestationObject: string): Promise<PublicKey> {
    const decodedAttestationObj =  cbor.decodeAllSync(toBuffer(attestationObject));

    const { authData } = decodedAttestationObj[0];

    const dataView = new DataView(
        new ArrayBuffer(2));
    const idLenBytes = authData.slice(53, 55);
    idLenBytes.forEach(
        (value: any, index: any) => dataView.setUint8(
            index, value));
    const credentialIdLength = dataView.getUint16(0);

    const publicKeyBytes = authData.slice(55 + credentialIdLength) as Uint8Array;

    const struct = cbor.decodeAllSync(publicKeyBytes)[0];
    
    const x = struct.get(COSEKEYS.x);
    const y = struct.get(COSEKEYS.y);
 
    const pk = ec.keyFromPublic({ x, y });

    // x and y coordinates
    const publicKey = [
      "0x" + pk.getPublic("hex").slice(2, 66),
      "0x" + pk.getPublic("hex").slice(-64),
    ];
    
    return {
        x: publicKey[0],
        y: publicKey[1],
    }
}

export async function getWebAuthnAssertion(challenge: string, options?: CredentialRequestConfig): Promise<WebAuthnSignaturePayload> {
    const webAuthnSupported = hasWebAuthnSupport();
  
    if (!webAuthnSupported) {
      throw new Error("The browser does not support WebAuthn");
    }
  
    const signingOptions = getCredentialRequestOptions(challenge, options);
    const clientGetResult = await webauthnCredentialGet(signingOptions);
    const assertion = clientGetResult.toJSON();
    const signaturePayload: WebAuthnSignaturePayload = {
      authenticatorData: assertion.response.authenticatorData,
      clientDataJson: assertion.response.clientDataJSON,
      credentialId: assertion.id,
      signature: assertion.response.signature,
    };
  
    return signaturePayload;
}

export async function parseSignature(signature: string): Promise<Signature> {
    const parsedSignature = AsnParser.parse(
        toBuffer(signature),
        ECDSASigValue
      );
      let rBytes = new Uint8Array(parsedSignature.r);
      let sBytes = new Uint8Array(parsedSignature.s);
       
      if (shouldRemoveLeadingZero(rBytes)) {
        rBytes = rBytes.slice(1);
      }
       
      if (shouldRemoveLeadingZero(sBytes)) {
        sBytes = sBytes.slice(1);
      }

    return {
        r: "0x" + Buffer.from(rBytes).toString("hex"),
        s: "0x" + Buffer.from(sBytes).toString("hex"),
    }
}

export async function getMessageHash(authenticatorData: string, clientDataJSON: string): Promise<string> {
    const clientDataHash = toHash(toBuffer(clientDataJSON));
    const authDataBuffer: Uint8Array = toBuffer(authenticatorData);

    const signatureBase = concat([authDataBuffer, clientDataHash]);

    return "0x" + toHash(signatureBase).toString("hex");
} 

function protocolTransportEnumToInternalEnum(protocolEnum: ExternalAuthenticatorTransports): InternalAuthenticatorTransports {
    switch (protocolEnum) {
      case "internal": {
        return "AUTHENTICATOR_TRANSPORT_INTERNAL";
      }
      case "usb": {
        return "AUTHENTICATOR_TRANSPORT_USB";
      }
      case "nfc": {
        return "AUTHENTICATOR_TRANSPORT_NFC";
      }
      case "ble": {
        return "AUTHENTICATOR_TRANSPORT_BLE";
      }
      case "hybrid": {
        return "AUTHENTICATOR_TRANSPORT_HYBRID";
      }
      default: {
        throw new Error("unsupported transport format");
      }
    }
}

function toInternalAttestation(attestation: PublicKeyCredentialWithAttestationJSON): WebAuthnAttestation {
    return {
      credentialId: attestation.rawId,
      attestationObject: attestation.response.attestationObject,
      clientDataJson: attestation.response.clientDataJSON,
      transports: attestation.response.transports.map(
        protocolTransportEnumToInternalEnum
      ),
    };
}

function getCredentialRequestOptions(
    challenge: string,
    signingConfig?: CredentialRequestConfig 
  ): CredentialRequestOptions {
  
    let publicKeyData = {};

    if (signingConfig !== undefined && signingConfig !== null) {
        publicKeyData = {
            ...publicKeyData,
            ...signingConfig.publicKey
        }
    }
    
    const signingOptions: CredentialRequestOptions = {
      ...signingConfig,
      publicKey: {
        ...publicKeyData,
        challenge: Uint8Array.from(
            challenge, c => c.charCodeAt(0)),
      },
    };
  
    return signingOptions;
}

