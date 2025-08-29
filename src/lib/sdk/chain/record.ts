/* SPDX-License-Identifier: Apache-2.0 */
import { getContract, toHex } from "viem";
import type { Hex } from "viem";
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
  const [account] = await w.getAddresses();
  const tx = await w.writeContract({
    address: env.factory,
    abi: factoryAbi,
    functionName: "createRecord",
    account
  });
  await l1Public.waitForTransactionReceipt({ hash: tx });
  rec = await recordOf(owner);
  return rec;
}

export async function getSeq(recordAddr: Hex): Promise<number> {
  const c = getContract({ address: recordAddr, abi: patientRecordAbi, client: l1Public });
  const val = await c.read.seq(); // no args
  return Number(val);
}

export async function anchorEvent(recordAddr: Hex, contentHash: Uint8Array) {
  const w = walletL1();
  const [account] = await w.getAddresses();
  const tx = await w.writeContract({
    address: recordAddr,
    abi: patientRecordAbi,
    functionName: "anchor",
    args: [toHex(contentHash), BigInt(env.l2Id)],
    account
  });
  return l1Public.waitForTransactionReceipt({ hash: tx });
}
