import { useState } from "react";
import {
  createPublicClient,
  createWalletClient,
  getContract,
  custom,
  http,
  toHex,
  hexToBytes,
} from "viem";
import type { Hex } from "viem";
import stringify from "json-stable-stringify";
import { hash as sha256Bytes } from "./lib/sdk/crypto/hash"; // Uint8Array sha256

// ────────────────────────────────────────────────────────────────────────────────
// ENV (Vite)
// ────────────────────────────────────────────────────────────────────────────────
const env = {
  l1Id: Number(import.meta.env.VITE_L1_CHAIN_ID), // e.g. 11155111 (Sepolia)
  l1Url: import.meta.env.VITE_L1_RPC_URL as string,
  l2Id: Number(import.meta.env.VITE_L2_CHAIN_ID), // e.g. 84532 (Base Sepolia)
  l2Url: import.meta.env.VITE_L2_RPC_URL as string,
  factory: import.meta.env.VITE_FACTORY_ADDRESS as `0x${string}`,
  vault: import.meta.env.VITE_VAULT_ADDRESS as `0x${string}`,
};

const ZERO_ADDR = "0x0000000000000000000000000000000000000000" as const;

// Help MetaMask add/switch chains if needed
const PRESETS: Record<number, { chainName: string; explorer: string; symbol: string }> = {
  11155111: { chainName: "Sepolia",      explorer: "https://sepolia.etherscan.io",  symbol: "ETH" },
  84532:    { chainName: "Base Sepolia", explorer: "https://sepolia.basescan.org",  symbol: "ETH" },
};

// ────────────────────────────────────────────────────────────────────────────────
// Minimal ABIs (match on-chain contracts exactly)
// ────────────────────────────────────────────────────────────────────────────────
const factoryAbi = [
  { type: "function", name: "recordOf", stateMutability: "view", inputs: [{ name: "owner", type: "address" }], outputs: [{ type: "address" }] },
  { type: "function", name: "createRecord", stateMutability: "nonpayable", inputs: [], outputs: [{ type: "address" }] },
] as const;

const patientRecordAbi = [
  { type: "function", name: "seq", stateMutability: "view", inputs: [], outputs: [{ type: "uint64" }] },
  { type: "function", name: "contentHashAt", stateMutability: "view", inputs: [{ type: "uint64" }], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "anchor", stateMutability: "nonpayable", inputs: [{ type: "bytes32" }, { type: "uint32" }], outputs: [{ type: "uint64" }] },
] as const;

// Vault (L2): write + reads
const vaultWriteAbi = [
  // function put(bytes ciphertext, bytes16 tag) external returns (bytes32 envelopeId)
  { type: "function", name: "put", stateMutability: "nonpayable", inputs: [{ name: "ciphertext", type: "bytes" }, { name: "tag", type: "bytes16" }], outputs: [{ type: "bytes32" }] },
] as const;
const vaultReadAbi = [
  { type: "function", name: "getCiphertextByTag", stateMutability: "view", inputs: [{ type: "bytes16" }], outputs: [{ type: "bytes" }] },
  { type: "function", name: "getEnvelopeIdByTag", stateMutability: "view", inputs: [{ type: "bytes16" }], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "getCiphertext",      stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ type: "bytes" }] },
] as const;

// ────────────────────────────────────────────────────────────────────────────────
// viem clients & wallet helpers
// ────────────────────────────────────────────────────────────────────────────────
const l1Public = createPublicClient({ chain: { id: env.l1Id } as any, transport: http(env.l1Url) });
const l2Public = createPublicClient({ chain: { id: env.l2Id } as any, transport: http(env.l2Url) });

function walletL1() {
  const eth = (window as any).ethereum; if (!eth) throw new Error("MetaMask not found");
  return createWalletClient({ chain: { id: env.l1Id } as any, transport: custom(eth) });
}
function walletL2() {
  const eth = (window as any).ethereum; if (!eth) throw new Error("MetaMask not found");
  return createWalletClient({ chain: { id: env.l2Id } as any, transport: custom(eth) });
}

async function ensureChain(targetId: number, rpcUrl?: string) {
  const eth = (window as any).ethereum; if (!eth) throw new Error("MetaMask not found");
  const curHex: string = await eth.request({ method: "eth_chainId" });
  const cur = parseInt(curHex, 16);
  if (cur === targetId) return;
  const chainIdHex = `0x${targetId.toString(16)}`;
  try {
    await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId: chainIdHex }] });
  } catch (e: any) {
    if (e?.code === 4902) {
      const p = PRESETS[targetId] || { chainName: `Chain ${targetId}`, explorer: "", symbol: "ETH" };
      await eth.request({ method: "wallet_addEthereumChain", params: [{ chainId: chainIdHex, chainName: p.chainName, rpcUrls: rpcUrl ? [rpcUrl] : [""], nativeCurrency: { name: p.symbol, symbol: p.symbol, decimals: 18 }, blockExplorerUrls: p.explorer ? [p.explorer] : [] }] });
      await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId: chainIdHex }] });
    } else { throw e; }
  }
}

// Quick on-chain code checks to fail fast on wrong addresses
async function assertCodeAtL1(addr: `0x${string}`) {
  const code = await l1Public.getBytecode({ address: addr });
  if (!code) throw new Error(`No contract code at ${addr} on L1 chain ${env.l1Id}.`);
}
async function assertCodeAtL2(addr: `0x${string}`) {
  const code = await l2Public.getBytecode({ address: addr });
  if (!code) throw new Error(`No contract code at ${addr} on L2 chain ${env.l2Id}.`);
}

// ────────────────────────────────────────────────────────────────────────────────
// Crypto helpers & deterministic derivation (CURRENT METHOD ONLY)
// ────────────────────────────────────────────────────────────────────────────────
const enc = new TextEncoder();
const dec = new TextDecoder();

function concatBytes(...arrs: Uint8Array[]) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0; for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}
function u64be(n: number) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), false); return b; }

// Off-chain wallet-bound root via EIP-712 (session-only secret)
async function deriveRootViaSignature(recordAddr: Hex): Promise<Uint8Array> {
  await ensureChain(env.l1Id, env.l1Url); // ensure chainId in domain matches wallet
  const w = walletL1();
  const [from] = await w.getAddresses();
  const sig = await (w as any).signTypedData({
    account: from,
    domain: { name: "PrometheusChains", version: "1", chainId: env.l1Id, verifyingContract: recordAddr },
    types: { Derive: [{ name: "purpose", type: "string" }, { name: "record", type: "address" }, { name: "l2", type: "uint256" }] },
    primaryType: "Derive",
    message: { purpose: "pc-key-derivation-v1", record: recordAddr, l2: BigInt(env.l2Id) },
  });
  return await sha256Bytes(hexToBytes(sig as Hex)); // 32-byte root
}

// CURRENT derivation: (root, recordAddr, index) → tag(16), key(32), nonce(12)
async function deriveTagKeyNonceFromRootIndex(
  root: Uint8Array,
  recordAddr: Hex,
  i: number
): Promise<{ tagHex: Hex; keyBytes: Uint8Array; nonce: Uint8Array }> {
  const base = concatBytes(enc.encode("PC-DERIVE-ROOT-I"), root, hexToBytes(recordAddr), u64be(i));
  const tag   = (await sha256Bytes(concatBytes(enc.encode("TAG"), base))).slice(0, 16); // bytes16
  const key   =  await sha256Bytes(concatBytes(enc.encode("KEY"), base));               // 32 bytes
  const nonce = (await sha256Bytes(concatBytes(enc.encode("NONCE"), base))).slice(0, 12); // 12 bytes
  return { tagHex: toHex(tag) as Hex, keyBytes: key, nonce };
}

async function aesGcmEncrypt(keyBytes: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const ct  = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plaintext);
  return new Uint8Array(ct);
}
async function aesGcmDecrypt(keyBytes: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const pt  = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ciphertext);
  return new Uint8Array(pt);
}

function canonicalBytesFromJson(text: string): Uint8Array {
  const obj = JSON.parse(text);
  return enc.encode(stringify(obj, { space: 0 }));
}

// L2 vault read (fixed to current contract reads)
async function fetchCiphertextByTag(tagHex: Hex): Promise<Hex | null> {
  const vault = getContract({ address: env.vault as `0x${string}`, abi: vaultReadAbi as any, client: l2Public });
  try {
    const byTag = (await (vault as any).read.getCiphertextByTag([tagHex])) as Hex;
    if (byTag && byTag !== "0x") return byTag;
  } catch {}
  try {
    const envId = (await (vault as any).read.getEnvelopeIdByTag([tagHex])) as Hex;
    if (envId && envId !== ("0x" as any).padEnd(66, "0")) {
      const byId = (await (vault as any).read.getCiphertext([envId])) as Hex;
      if (byId && byId !== "0x") return byId;
    }
  } catch {}
  return null;
}

// ────────────────────────────────────────────────────────────────────────────────
// React component
// ────────────────────────────────────────────────────────────────────────────────
type RestoreRow = { i: number; ok: boolean; tag: string; ch: string; preview?: string; missing?: boolean };

export default function App() {
  const [account, setAccount]   = useState<Hex>(ZERO_ADDR);
  const [recordAddr, setRecord] = useState<Hex>(ZERO_ADDR);
  const [status, setStatus]     = useState<string>("");
  const [jsonText, setJson]     = useState<string>('{"resourceType":"Bundle","type":"collection","entry":[{"resource":{"resourceType":"Patient","id":"me"}}]}');
  const [hashHex, setHashHex]   = useState<string>("");
  const [l2Tag, setL2Tag]       = useState<string>("");
  const [lastTx, setLastTx]     = useState<string>("");

  // Session root (from wallet signature)
  const [root, setRoot] = useState<Uint8Array | null>(null);

  // Restore
  const [restoreResults, setRestoreResults] = useState<RestoreRow[]>([]);

  async function connect() {
    const eth = (window as any).ethereum; if (!eth) { alert("MetaMask not found"); return; }
    const [addr] = await eth.request({ method: "eth_requestAccounts" });
    setAccount(addr);
  }

  async function ensureRecord() {
    try {
      if (!account || account === ZERO_ADDR) return alert("Connect MetaMask first");
      setStatus("Switching to L1…");
      await ensureChain(env.l1Id, env.l1Url);

      setStatus("Checking factory…");
      await assertCodeAtL1(env.factory);

      setStatus("Checking/creating your L1 PatientRecord…");
      const factory = getContract({ address: env.factory, abi: factoryAbi, client: l1Public });
      let rec: Hex;
      try {
        rec = (await factory.read.recordOf([account])) as Hex;
      } catch (e: any) {
        throw new Error("recordOf() failed — verify chain & factory address. " + (e?.shortMessage || e?.message || String(e)));
      }

      if (rec === ZERO_ADDR) {
        const w = walletL1();
        const [from] = await w.getAddresses();
        let request;
        try {
          const sim = await l1Public.simulateContract({ address: env.factory, abi: factoryAbi, functionName: "createRecord", account: from });
          request = sim.request;
        } catch (e: any) {
          throw new Error("Simulation for createRecord() failed. " + (e?.shortMessage || e?.message || String(e)));
        }
        const txHash = await w.writeContract(request);
        setStatus("Tx sent to create record — waiting for confirmation…");
        setLastTx(txHash as string);
        await l1Public.waitForTransactionReceipt({ hash: txHash, confirmations: 1 });
        rec = (await factory.read.recordOf([account])) as Hex;
        if (rec === ZERO_ADDR) throw new Error("Record still zero after tx confirmation.");
      }

      setRecord(rec);
      setStatus(`✅ Record ready: ${rec}`);
    } catch (e: any) {
      console.error("ensureRecord error", e);
      setStatus("❌ " + (e?.shortMessage || e?.message || String(e)));
    }
  }

  async function authorizeKeyDerivation() {
    try {
      if (!recordAddr || recordAddr === ZERO_ADDR) return alert("Ensure your record first");
      setStatus("Requesting wallet signature for key derivation…");
      const r = await deriveRootViaSignature(recordAddr);
      setRoot(r);
      setStatus("🔑 Key derivation authorized for this session.");
    } catch (e: any) {
      console.error("sign error", e);
      setStatus("❌ Signature failed: " + (e?.shortMessage || e?.message || String(e)));
    }
  }

  async function hashAndAnchorL1() {
    try {
      if (!recordAddr || recordAddr === ZERO_ADDR) return alert("Ensure your record first");
      setStatus("Switching to L1…");
      await ensureChain(env.l1Id, env.l1Url);

      setStatus("Computing canonical hash…");
      const canonical = canonicalBytesFromJson(jsonText);
      const digest = await sha256Bytes(canonical);
      const hex = toHex(digest);
      setHashHex(hex);

      const w = walletL1();
      const [from] = await w.getAddresses();

      setStatus("Preflighting anchor call…");
      const { request } = await l1Public.simulateContract({ address: recordAddr, abi: patientRecordAbi, functionName: "anchor", args: [hex as Hex, env.l2Id], account: from });

      setStatus("Requesting wallet confirmation…");
      const txHash = await w.writeContract(request);
      setLastTx(txHash as string);

      setStatus("Tx sent — waiting for 1 confirmation…");
      await l1Public.waitForTransactionReceipt({ hash: txHash, confirmations: 1 });
      setStatus("✅ Anchored on L1. Now encrypt & store on L2 for this entry.");
      document.getElementById("quick-actions")?.scrollIntoView({ behavior: "smooth", block: "center" });
    } catch (e: any) {
      console.error("anchor error", e);
      setStatus("❌ L1 anchor failed: " + (e?.shortMessage || e?.message || String(e)));
    }
  }

  // Anchor-first only. We always store for index = current seq (just appended).
  async function encryptAndStoreL2() {
    try {
      if (!account || account === ZERO_ADDR) return alert("Connect MetaMask first");
      if (!recordAddr || recordAddr === ZERO_ADDR) return alert("Ensure your record first");
      if (!root) return alert("Click “Authorize key derivation (sign)” first.");

      // Determine current seq on L1; require at least 1 anchor.
      const rec = getContract({ address: recordAddr, abi: patientRecordAbi, client: l1Public });
      const seq = Number(await rec.read.seq());
      if (seq === 0) return alert("Anchor to L1 first, then store to L2.");
      const i = seq; // store for the just-anchored entry

      setStatus("Switching to L2…");
      await ensureChain(env.l2Id, env.l2Url);

      setStatus("Checking vault…");
      await assertCodeAtL2(env.vault);

      setStatus(`Encrypting snapshot #${i} and storing on L2…`);
      const canonical = canonicalBytesFromJson(jsonText);
      const { tagHex, keyBytes, nonce } = await deriveTagKeyNonceFromRootIndex(root!, recordAddr, i);
      const ciphertext = await aesGcmEncrypt(keyBytes, nonce, canonical);
      const ctHex = toHex(ciphertext);

      const w = walletL2();
      const [from] = await w.getAddresses();

      // put(bytes ciphertext, bytes16 tag) → returns bytes32 envelopeId
      const { request } = await l2Public.simulateContract({ address: env.vault as `0x${string}`, abi: vaultWriteAbi, functionName: "put", args: [ctHex as Hex, tagHex as Hex], account: from });
      const txHash = await w.writeContract(request);
      setLastTx(txHash as string);

      setStatus("Tx sent — waiting for L2 confirmation…");
      await l2Public.waitForTransactionReceipt({ hash: txHash, confirmations: 1 });
      setL2Tag(tagHex);
      setStatus(`✅ Stored snapshot #${i} on L2.`);
      document.getElementById("quick-actions")?.scrollIntoView({ behavior: "smooth", block: "center" });
    } catch (e: any) {
      console.error("l2 store error", e);
      setStatus("❌ L2 store failed: " + (e?.shortMessage || e?.message || String(e)));
    }
  }

  async function restoreFromWallet() {
    try {
      if (!recordAddr || recordAddr === ZERO_ADDR) return alert("Ensure your record first");
      if (!root) return alert("Click “Authorize key derivation (sign)” first.");
      setStatus("Restoring with wallet-bound derivation…");

      const rec = getContract({ address: recordAddr, abi: patientRecordAbi, client: l1Public });
      const seq = Number(await rec.read.seq());
      const out: RestoreRow[] = [];

      for (let i = 1; i <= seq; i++) {
        const chHex = (await rec.read.contentHashAt([BigInt(i)])) as Hex; // hash of PLAINTEXT
        const { tagHex, keyBytes, nonce } = await deriveTagKeyNonceFromRootIndex(root!, recordAddr, i);
        const ctHex = await fetchCiphertextByTag(tagHex as Hex);
        if (!ctHex || ctHex === "0x") { out.push({ i, ok: false, tag: tagHex, ch: chHex, missing: true }); continue; }

        const pt = await aesGcmDecrypt(keyBytes, nonce, hexToBytes(ctHex));
        const check = await sha256Bytes(pt);
        const ok = toHex(check).toLowerCase() === (chHex as string).toLowerCase();

        let preview: string | undefined; try { const j = JSON.parse(dec.decode(pt)); const s = JSON.stringify(j); preview = s.slice(0, 140) + (s.length > 140 ? "…" : ""); } catch {}
        out.push({ i, ok, tag: tagHex, ch: chHex, preview });
      }

      setRestoreResults(out);
      const okCount = out.filter(r => r.ok).length;
      setStatus(`✅ Restore complete (${okCount}/${out.length} verified)`);
    } catch (e: any) {
      console.error("restore error", e);
      setStatus("❌ Restore failed: " + (e?.shortMessage || e?.message || String(e)));
    }
  }

  function shortAddr(a: string) { return `${a.slice(0, 6)}…${a.slice(-4)}`; }
  function downloadBytes(bytes: Uint8Array, filename: string, mime = "application/octet-stream") {
    const blob = new Blob([bytes], { type: mime }); const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = filename; a.click(); URL.revokeObjectURL(url);
  }
  async function onDownloadCipher(r: RestoreRow) {
    try {
      const ctHex = await fetchCiphertextByTag(r.tag as Hex); if (!ctHex) return alert("Ciphertext not found in vault for this tag.");
      const fn = `record-${shortAddr(String(recordAddr))}-#${r.i}-${(r.ch as string).slice(2, 10)}.cipher.bin`;
      downloadBytes(hexToBytes(ctHex), fn);
    } catch (e: any) { alert("Download failed: " + (e?.shortMessage || e?.message || String(e))); }
  }
  async function onDownloadDecrypted(r: RestoreRow) {
    try {
      if (!root) return alert("Click “Authorize key derivation (sign)” first.");
      const { keyBytes, nonce } = await deriveTagKeyNonceFromRootIndex(root!, recordAddr, r.i);
      const ctHex = await fetchCiphertextByTag(r.tag as Hex); if (!ctHex) return alert("Ciphertext not found in vault for this tag.");
      const pt = await aesGcmDecrypt(keyBytes, nonce, hexToBytes(ctHex));
      const digest = await sha256Bytes(pt);
      const ok = toHex(digest).toLowerCase() === (r.ch as string).toLowerCase();
      if (!ok) return alert("Hash mismatch — refusing to export plaintext.");
      const fn = `record-${shortAddr(String(recordAddr))}-#${r.i}-${(r.ch as string).slice(2, 10)}.fhir.json`;
      downloadBytes(pt, fn, "application/fhir+json");
    } catch (e: any) { alert("Download failed: " + (e?.shortMessage || e?.message || String(e))); }
  }

  return (
    <div style={{ padding: 24, fontFamily: "system-ui, sans-serif", maxWidth: 900, margin: "0 auto" }}>
      <h1>Prometheus’ Chains — Patient Web MVP</h1>

      <div style={{ marginBottom: 12 }}>
        <button onClick={connect}>Connect Wallet</button>{" "}
        <button onClick={ensureRecord}>Check / Create L1 PatientRecord</button>{" "}
        <button onClick={authorizeKeyDerivation} disabled={!recordAddr || recordAddr === ZERO_ADDR}>
          Authorize key derivation (sign)
        </button>
      </div>

      <div style={{ opacity: 0.85, marginBottom: 16 }}>
        <div><b>Account:</b> {account}</div>
        <div><b>Record:</b> {recordAddr}</div>
        <div><b>Env:</b> L1={env.l1Id} · L2={env.l2Id}</div>
        {root ? <div style={{color:"#0a0"}}>🔑 Key derivation active (session)</div> : null}
      </div>

      <h3>Paste FHIR JSON (plaintext)</h3>
      <textarea rows={10} style={{ width: "100%" }} value={jsonText} onChange={(e) => setJson(e.target.value)} />

      <div style={{ marginTop: 12 }}>
        <button onClick={hashAndAnchorL1}>Generate Hash & Anchor to L1</button>{" "}
        <button onClick={encryptAndStoreL2}>Encrypt & Store to L2 Vault</button>
      </div>

      {hashHex && <p style={{ marginTop: 8, wordBreak: "break-all" }}><b>contentHash (L1):</b> {hashHex}</p>}
      {l2Tag &&  <p style={{ marginTop: 8, wordBreak: "break-all" }}><b>tag (L2):</b> {l2Tag}</p>}
      {lastTx && <p style={{ marginTop: 8, wordBreak: "break-all" }}><b>last tx:</b> {lastTx}</p>}

      <hr style={{ margin: "24px 0" }} />

      <h3>Restore</h3>
      <p style={{ opacity: 0.8, marginTop: -6 }}>
        We derive tag/key/nonce from your wallet signature (off-chain) + record + <b>index</b>, fetch ciphertext by tag from L2, decrypt locally, then verify hash against L1.
      </p>
      <div style={{ marginTop: 8 }}>
        <button onClick={restoreFromWallet}>Restore timeline</button>
      </div>

      {restoreResults.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <b>Restored entries:</b>
          <ul>
            {restoreResults.map((r) => (
              <li key={r.i} style={{ margin: "6px 0" }}>
                #{r.i} — tag {r.tag} — {r.ok ? "✅ verified" : r.missing ? "⚠️ missing on L2" : "❌ hash mismatch"}
                {r.preview && (<div style={{ fontSize: 12, opacity: 0.8, wordBreak: "break-all" }}>preview: {r.preview}</div>)}
                <div style={{ marginTop: 4 }}>
                  <button onClick={() => onDownloadCipher(r)}>⬇ ciphertext</button>{" "}
                  <button onClick={() => onDownloadDecrypted(r)} disabled={!r.ok}>⬇ FHIR JSON</button>
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      <p style={{ marginTop: 8 }}>{status}</p>

      <div id="quick-actions" style={{ marginTop: 8, padding: 12, borderRadius: 12, border: "1px solid rgba(0,0,0,0.1)", background: "linear-gradient(180deg, rgba(0,0,0,0.03), rgba(0,0,0,0.01))" }}>
        <b>Quick actions</b>
        <div style={{ marginTop: 8 }}>
          <button onClick={hashAndAnchorL1}>Generate Hash & Anchor to L1</button>{" "}
          <button onClick={encryptAndStoreL2}>Encrypt & Store to L2</button>
        </div>
        <div style={{ fontSize: 12, opacity: 0.75, marginTop: 6 }}>
          Order: <b>Anchor on L1 first</b> for the snapshot you just pasted, then <b>Store on L2</b> for that same index.
        </div>
      </div>
    </div>
  );
}
