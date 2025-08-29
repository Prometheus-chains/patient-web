/* SPDX-License-Identifier: Apache-2.0 */
import { getContract, Hex, toHex } from "viem";
import { env } from "../../env";
import { vaultAbi } from "./abis";
import { l2Public, walletL2, switchTo } from "./client";

/** Store ciphertext on L2 under a private tag */
export async function vaultPut(tag: Uint8Array, ciphertext: Uint8Array) {
  await switchTo(env.l2Id);
  const w = walletL2();
  const hash = await w.writeContract({
    address: env.vault as Hex, abi: vaultAbi, functionName: "put",
    args: [toHex(tag), toHex(ciphertext)]
  });
  return l2Public.waitForTransactionReceipt({ hash });
}
