import type { KeyObject } from "node:crypto";

export declare const E2EE_VERSION: string;
export declare const X25519_SUITE: string;

export declare class E2eeError extends Error {}

export interface KeysetKey {
  key_id: string;
  algo: string;
  public_key: string;
}

export interface AttestedKeyset {
  e2ee_public_keys?: KeysetKey[];
  [key: string]: unknown;
}

/// The client half of one encrypted exchange: the static key the response is
/// encrypted to, and the request context every field's associated data binds.
export interface ClientKey {
  privateKey: KeyObject;
  publicKey: string;
  algo: string;
  keyId: string;
  model: string;
  nonce: string;
  ts: number;
}

export interface SealedRequest {
  /// The body to send, with every message content replaced by its envelope.
  bytes: Buffer;
  /// The compact plaintext body the workload restores and hashes into the
  /// receipt (§8 of the E2EE v2 protocol).
  restored: Buffer;
  /// All five headers a v2 request must carry; without any one of them the
  /// service rejects the request.
  headers: Record<string, string>;
  clientKey: ClientKey;
}

export declare function selectE2eeKey(keyset: AttestedKeyset): KeysetKey;

/// §5 restoration: a decrypted whole-content plaintext that parses as a JSON
/// array comes back as structured content, and anything else stays a string.
export declare function restoreContent(plaintext: string): string | unknown[];

export declare function encryptChatRequest(
  body: Record<string, unknown>,
  keyset: AttestedKeyset,
  options?: { now?: number; rand?: (length: number) => Uint8Array },
): SealedRequest;

export declare function decryptResponse(
  bodyBytes: Uint8Array | string,
  clientKey: ClientKey,
  options?: { model?: string },
): Record<string, unknown>;

export declare function requestAad(input: {
  algo: string;
  model: string;
  field: string;
  nonce: string;
  ts: number;
}): Uint8Array;

export declare function responseAad(input: {
  algo: string;
  model: string;
  id: string;
  field: string;
  nonce: string;
  ts: number;
}): Uint8Array;

export declare function sealField(
  recipientRaw: Uint8Array,
  plaintext: string,
  aad: Uint8Array,
  rand?: (length: number) => Uint8Array,
): string;

export declare function openField(privateKey: KeyObject, envelopeHex: string, aad: Uint8Array): string;

export declare function publicKeyFromRaw(raw: Uint8Array): KeyObject;
export declare function privateKeyFromSeed(seed: Uint8Array): KeyObject;
export declare function rawPublicKey(key: KeyObject): Uint8Array;
