/* SPDX-License-Identifier: Apache-2.0 */
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

/** Derive tag(32) | key(32) | nonce(24) from healthRoot + record + seq + contentHash */
export function deriveTagKeyNonce(
  healthRoot: Uint8Array,
  recordAddr: `0x${string}`,
  seq: number,
  contentHash: Uint8Array
) {
  const info = new TextEncoder().encode(`prometheus/v1|${recordAddr.toLowerCase()}|${seq}`);
  const okm = hkdf(sha256, healthRoot, contentHash, info, 88);
  return { tag: okm.slice(0, 32), key: okm.slice(32, 64), nonce: okm.slice(64, 88) };
}
