/* SPDX-License-Identifier: Apache-2.0 */
import { xchacha20poly1305 } from "@noble/ciphers/chacha";

/** Encrypt with XChaCha20-Poly1305 (AEAD) */
export function encrypt(plaintext: Uint8Array, key: Uint8Array, nonce: Uint8Array): Uint8Array {
  return xchacha20poly1305(key).seal(nonce, plaintext);
}
export function decrypt(ciphertext: Uint8Array, key: Uint8Array, nonce: Uint8Array): Uint8Array {
  const out = xchacha20poly1305(key).open(nonce, ciphertext);
  if (!out) throw new Error("decryption failed");
  return out;
}
