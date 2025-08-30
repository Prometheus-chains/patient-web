/* SPDX-License-Identifier: Apache-2.0 */
import { toHex } from "viem";
import { env } from "../../env";
import { vaultAbi } from "./abis";
import { l2Public, walletL2, switchTo } from "./client";
export async function vaultPut(tag, ciphertext) {
    await switchTo(env.l2Id);
    const w = walletL2();
    const [account] = await w.getAddresses();
    const hash = await w.writeContract({
        address: env.vault,
        abi: vaultAbi,
        functionName: "put",
        args: [toHex(tag), toHex(ciphertext)],
        account,
        chain: undefined
    });
    return l2Public.waitForTransactionReceipt({ hash });
}
