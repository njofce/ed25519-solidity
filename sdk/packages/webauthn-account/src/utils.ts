import base64 from "@hexagon/base64";
import * as cr from "crypto";

export function hasWebAuthnSupport(): boolean {
    return !!window.PublicKeyCredential;
}

export function generateRandomBuffer (): ArrayBuffer {
    const arr = new Uint8Array(32);
    crypto.getRandomValues(arr);
    return arr.buffer;
  };

export function base64UrlEncode (challenge: ArrayBuffer): string {
    return Buffer.from(challenge)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
};

export function toHexString(byteArray: Uint8Array) {
  return byteArray.reduce((output, elem) => 
    (output + ('0' + elem.toString(16)).slice(-2)),
    '');
}

export function bytesToHex (bytes: Uint8Array): string {
  return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, "0"), "");
}

export function toBuffer(
  base64urlString: string,
  from: "base64" | "base64url" = "base64url"
): Uint8Array {
  const _buffer = base64.toArrayBuffer(base64urlString, from === "base64url");
  return new Uint8Array(_buffer);
}

export function toHash(data: cr.BinaryLike, algo = "SHA256") {
  return cr.createHash(algo).update(data).digest();
}

export function concat(arrays: Uint8Array[]): Uint8Array {
  let pointer = 0;
  const totalLength = arrays.reduce((prev, curr) => prev + curr.length, 0);
 
  const toReturn = new Uint8Array(totalLength);
 
  arrays.forEach((arr) => {
    toReturn.set(arr, pointer);
    pointer += arr.length;
  });
 
  return toReturn;
}

export function shouldRemoveLeadingZero(bytes: Uint8Array): boolean {
  return bytes[0] === 0x0 && (bytes[1] & (1 << 7)) !== 0;
}