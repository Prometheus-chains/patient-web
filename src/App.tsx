import { useState } from "react";
import {
  createPublicClient, createWalletClient, getContract,
  custom, http, Hex, toHex
} from "viem";
import stringify from "json-stable-stringify";
import { sha256 } from "@noble/hashes/sha256";

// --- ENV from Vite (set these in Vercel) ---
const env = {
  l1Id: Number(import.meta.env.VITE_L1_CHAIN_ID),              // e.g. 11155111 (Sepolia)
  l1Url: import.meta.env.VITE_L1_RPC_URL as string,
  l2Id: Number(import.meta.env.VITE_L2_CHAIN_ID),              // e.g. 84532 (Base Sepolia)
  factory: import.meta.env.VITE_FACTORY_ADDRESS as `0x${string}`,
};

// --- Minimal ABIs for Factory & PatientRecord ---
const factoryAbi = [
  { type: "function", name: "recordOf", stateMutability: "view",
    inputs: [{ name: "owner", type: "address" }], outputs: [{ type: "address" }] },
  { type: "function", name: "createRecord", stateMutability: "nonpayable", inputs: [], outputs: [] },
] as const;

const patientRecordAbi = [
  { type: "function", name: "seq", stateMutability: "view", inputs: [], outputs: [{ type: "uint64" }] },
  { type: "function", name: "contentHashAt", stateMutability: "view",
    inputs: [{ type: "uint64" }], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "anchor", stateMutability: "nonpayable",
    inputs: [{ type: "bytes32" }, { type: "uint256" }], outputs: [] },
] as const;

// --- VIEM clients ---
const l1Public = createPublicClient({ chain: { id: env.l1Id } as any, transport: http(env.l1Url) });
function walletL1() {
  if (!window.ethereum) throw new Error("MetaMask not found");
  return createWalletClient({ chain: { id: env.l1Id } as any, transport: custom(window.ethereum) });
}

export default function App() {
  const [account, setAccount]   = useState<Hex>("0x0000000000000000000000000000000000000000");
  const [recordAddr, setRecord] = useState<Hex>("0x0000000000000000000000000000000000000000");
  const [status, setStatus]     = useState<string>("");
  const [jsonText, setJson]     = useState<string>(
    '{"resourceType":"Bundle","type":"collection","entry":[{"resource":{"resourceType":"Patient","id":"me"}}]}'
  );
  const [hashHex, setHashHex]   = useState<string>("");

  async function connect() {
    const eth = (window as any).ethereum;
    if (!eth) { alert("MetaMask not found"); return; }
    const [addr] = await eth.request({ method: "eth_requestAccounts" });
    setAccount(addr);
  }

  async function ensureRecord() {
    if (!account || account === "0x0000000000000000000000000000000000000000") {
      return alert("Connect MetaMask first");
    }
    setStatus("Checking/creating your L1 PatientRecord…");
    const factory = getContract({ address: env.factory, abi: factoryAbi, client: l1Public });
    let rec = await factory.read.recordOf([account]) as Hex;

    if (rec === "0x0000000000000000000000000000000000000000") {
      const w = walletL1();
      const txHash = await w.writeContract({ address: env.factory, abi: factoryAbi, functionName: "createRecord" });
      await l1Public.waitForTransactionReceipt({ hash: txHash });
      rec = await factory.read.recordOf([account]) as Hex;
    }
    setRecord(rec);
    setStatus(`✅ Record ready: ${rec}`);
  }

  function computeHash() {
    try {
      const obj = JSON.parse(jsonText);
      // canonicalize (stable key order, no spaces) → bytes:
      const canonical = new TextEncoder().encode(stringify(obj, { space: 0 }));
      const digest = sha256(canonical);                 // Uint8Array(32)
      const hex = toHex(digest);                        // 0x…
      setHashHex(hex);
      setStatus("✅ Canonical hash computed (ready to encrypt, store, anchor)");
    } catch (e: any) {
      setStatus("❌ JSON parse/canonicalize failed: " + (e?.message || String(e)));
    }
  }

  // (Optional) Anchor the hash now — useful to test L1 writes before wiring the vault/L2.
  async function anchorHash() {
    if (!recordAddr || recordAddr === "0x0000000000000000000000000000000000000000") {
      return alert("Ensure your record first");
    }
    if (!hashHex) { return alert("Compute the hash first"); }
    setStatus("Anchoring hash on L1…");
    const w = walletL1();
    const c = getContract({ address: recordAddr, abi: patientRecordAbi, client: w });
    const txHash = await w.writeContract({
      address: recordAddr, abi: patientRecordAbi, functionName: "anchor",
      args: [hashHex as Hex, BigInt(env.l2Id)]
    });
    await l1Public.waitForTransactionReceipt({ hash: txHash });
    setStatus("✅ Anchored on L1. (Next: encrypt + store on L2, then anchor.)");
  }

  return (
    <div style={{ padding: 24, fontFamily: "system-ui, sans-serif", maxWidth: 900, margin: "0 auto" }}>
      <h1>Prometheus’ Chains — Patient Web MVP</h1>

      <div style={{ marginBottom: 12 }}>
        <button onClick={connect}>Connect MetaMask</button>{" "}
        <button onClick={ensureRecord}>Ensure PatientRecord</button>{" "}
      </div>

      <div style={{ opacity: .8, marginBottom: 16 }}>
        <div><b>Account:</b> {account}</div>
        <div><b>Record:</b> {recordAddr}</div>
        <div><b>Env:</b> L1={env.l1Id} · L2={env.l2Id}</div>
      </div>

      <h3>Paste JSON (e.g., a FHIR Bundle)</h3>
      <textarea rows={8} style={{ width: "100%" }} value={jsonText} onChange={e => setJson(e.target.value)} />

      <div style={{ marginTop: 12 }}>
        <button onClick={computeHash}>Compute Canonical SHA-256</button>{" "}
        <button onClick={anchorHash} disabled={!hashHex || recordAddr === "0x0000000000000000000000000000000000000000"}>
          Anchor Hash (L1)
        </button>
      </div>

      {hashHex && <p style={{ marginTop: 8, wordBreak: "break-all" }}><b>contentHash:</b> {hashHex}</p>}
      <p style={{ marginTop: 8 }}>{status}</p>
    </div>
  );
}
