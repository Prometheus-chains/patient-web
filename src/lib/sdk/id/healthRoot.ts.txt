/* SPDX-License-Identifier: Apache-2.0 */
import { mnemonicToSeedSync } from "@scure/bip39";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

/** Turn a 12/24-word mnemonic into a 32-byte health root (no wallet keys here) */
export function deriveHealthRoot(mnemonic: string): Uint8Array {
  const seed = mnemonicToSeedSync(mnemonic); // 64 bytes
  const salt = new TextEncoder().encode("prometheus-chains/health-root");
  const info = new TextEncoder().encode("v1");
  return hkdf(sha256, seed, salt, info, 32);
}
