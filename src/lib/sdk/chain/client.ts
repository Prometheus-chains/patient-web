/* SPDX-License-Identifier: Apache-2.0 */
import { createPublicClient, createWalletClient, custom, http } from "viem";
import { env } from "../../env";

export const l1Public = createPublicClient({ chain: { id: env.l1Id } as any, transport: http(env.l1Url) });
export const l2Public = createPublicClient({ chain: { id: env.l2Id } as any, transport: http(env.l2Url) });

export function walletL1() {
  if (!window.ethereum) throw new Error("MetaMask not found");
  return createWalletClient({ chain: { id: env.l1Id } as any, transport: custom(window.ethereum) });
}
export function walletL2() {
  if (!window.ethereum) throw new Error("MetaMask not found");
  return createWalletClient({ chain: { id: env.l2Id } as any, transport: custom(window.ethereum) });
}

export async function switchTo(chainId: number) {
  const hex = "0x" + chainId.toString(16);
  await window.ethereum?.request({ method: "wallet_switchEthereumChain", params: [{ chainId: hex }] });
}
