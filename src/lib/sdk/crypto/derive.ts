/* SPDX-License-Identifier: Apache-2.0 */
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes";

/** tag(32) | key(32) | nonce(12) for AES-GCM */
export function deriveTagKeyNonce(
  healthRoot: Uint8Array,
  recordAddr: `0x${string}`,
  seq: number,
  contentHash: Uint8Array
) {
  const info = new TextEncoder().encode(`prometheus/v1|${recordAddr.toLowerCase()}|${seq}`);
  const okm = hkdf(sha256, healthRoot, contentHash, info, 32 + 32 + 12);
  return { tag: okm.slice(0, 32), key: okm.slice(32, 64), nonce: okm.slice(64, 76) };
}