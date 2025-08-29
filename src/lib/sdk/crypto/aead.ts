/* SPDX-License-Identifier: Apache-2.0 */
// AES-GCM (12-byte nonce), returns Uint8Array
export async function encrypt(plaintext: Uint8Array, key: Uint8Array, nonce: Uint8Array) {
  const k = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, k, plaintext);
  return new Uint8Array(ct);
}
export async function decrypt(ciphertext: Uint8Array, key: Uint8Array, nonce: Uint8Array) {
  const k = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, k, ciphertext);
  return new Uint8Array(pt);
}