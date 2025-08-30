/* SPDX-License-Identifier: Apache-2.0 */
import { getContract, toHex } from "viem";
import { l1Public, walletL1 } from "./client";
import { env } from "../../env";
import { factoryAbi, patientRecordAbi } from "./abis";
export async function recordOf(owner) {
    const c = getContract({ address: env.factory, abi: factoryAbi, client: l1Public });
    return (await c.read.recordOf([owner]));
}
export async function ensureRecord(owner) {
    let rec = await recordOf(owner);
    if (rec !== "0x0000000000000000000000000000000000000000")
        return rec;
    const w = walletL1();
    const [account] = await w.getAddresses();
    const hash = await w.writeContract({
        address: env.factory,
        abi: factoryAbi,
        functionName: "createRecord",
        account,
        chain: undefined
    });
    await l1Public.waitForTransactionReceipt({ hash });
    rec = await recordOf(owner);
    return rec;
}
export async function getSeq(recordAddr) {
    const c = getContract({ address: recordAddr, abi: patientRecordAbi, client: l1Public });
    const val = await c.read.seq();
    return Number(val);
}
export async function anchorEvent(recordAddr, contentHash) {
    const w = walletL1();
    const [account] = await w.getAddresses();
    const hash = await w.writeContract({
        address: recordAddr,
        abi: patientRecordAbi,
        functionName: "anchor",
        args: [toHex(contentHash), BigInt(env.l2Id)],
        account,
        chain: undefined
    });
    return l1Public.waitForTransactionReceipt({ hash });
}
