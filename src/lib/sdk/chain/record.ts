/* SPDX-License-Identifier: Apache-2.0 */
import { getContract, Hex, toHex } from "viem";
import { l1Public, walletL1 } from "./client";
import { env } from "../../env";
import { factoryAbi, patientRecordAbi } from "./abis";

export async function recordOf(owner: Hex): Promise<Hex> {
  const c = getContract({ address: env.factory, abi: factoryAbi, client: l1Public });
  return (await c.read.recordOf([owner])) as Hex;
}

export async function ensureRecord(owner: Hex): Promise<Hex> {
  let rec = await recordOf(owner);
  if (rec !== "0x0000000000000000000000000000000000000000") return rec;
  const w = walletL1();
  const hash = await w.writeContract({ address: env.factory, abi: factoryAbi, functionName: "createRecord", args: [] });
  await l1Public.waitForTransactionReceipt({ hash });
  rec = await recordOf(owner);
  return rec;
}

export async function getSeq(recordAddr: Hex): Promise<number> {
  const c = getContract({ address: recordAddr, abi: patientRecordAbi, client: l1Public });
  const x = await c.read.seq([]);
  return Number(x);
}

export async function anchorEvent(recordAddr: Hex, contentHash: Uint8Array) {
  const w = walletL1();
  const hash = await w.writeContract({
    address: recordAddr, abi: patientRecordAbi, functionName: "anchor",
    args: [toHex(contentHash), BigInt(env.l2Id)]
  });
  return hash;
}
