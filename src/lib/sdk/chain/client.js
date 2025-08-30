/* SPDX-License-Identifier: Apache-2.0 */
import { createPublicClient, createWalletClient, custom, http } from "viem";
import { env } from "../../env";
export const l1Public = createPublicClient({ chain: { id: env.l1Id }, transport: http(env.l1Url) });
export const l2Public = createPublicClient({ chain: { id: env.l2Id }, transport: http(env.l2Url) });
export function walletL1() {
    const eth = window.ethereum;
    if (!eth)
        throw new Error("MetaMask not found");
    return createWalletClient({ chain: { id: env.l1Id }, transport: custom(eth) });
}
export function walletL2() {
    const eth = window.ethereum;
    if (!eth)
        throw new Error("MetaMask not found");
    return createWalletClient({ chain: { id: env.l2Id }, transport: custom(eth) });
}
export async function switchTo(chainId) {
    const hex = "0x" + chainId.toString(16);
    await window.ethereum?.request({ method: "wallet_switchEthereumChain", params: [{ chainId: hex }] });
}
