/* SPDX-License-Identifier: Apache-2.0 */
// Derive tag(32) | key(32) | nonce(12) using HKDF-SHA256 via Web Crypto.
export async function deriveTagKeyNonce(
  healthRoot: Uint8Array,
  recordAddr: `0x${string}`,
  seq: number,
  contentHash: Uint8Array
): Promise<{ tag: Uint8Array; key: Uint8Array; nonce: Uint8Array }> {
  const info = new TextEncoder().encode(`prometheus/v1|${recordAddr.toLowerCase()}|${seq}`);
  // Import base key (IKM)
  const baseKey = await crypto.subtle.importKey("raw", healthRoot, "HKDF", false, ["deriveBits"]);
  // Derive output key material (OKM)
  const bitLen = (32 + 32 + 12) * 8;
  const okmBuf = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: contentHash, info },
    baseKey,
    bitLen
  );
  const okm = new Uint8Array(okmBuf);
  return {
    tag:   okm.slice(0, 32),
    key:   okm.slice(32, 64),
    nonce: okm.slice(64, 76), // 12-byte AES-GCM nonce
  };
}
