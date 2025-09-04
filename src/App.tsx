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

// ------- Types -------
type RestoreRow = {
  i: number;
  ok: boolean;
  tag: string;
  ch: string;
  preview?: string;
  missing?: boolean;
  mode?: "root-index" | "root-ch" | "legacy";
};

// --- ENV from Vite ---
const env = {
  l1Id: Number(import.meta.env.VITE_L1_CHAIN_ID),
  l1Url: import.meta.env.VITE_L1_RPC_URL as string,
  l2Id: Number(import.meta.env.VITE_L2_CHAIN_ID),
  l2Url: import.meta.env.VITE_L2_RPC_URL as string,
  factory: import.meta.env.VITE_FACTORY_ADDRESS as `0x${string}`,
  vault: (import.meta.env.VAULT_ADDRESS as `0x${string}`) ?? (import.meta.env.VITE_VAULT_ADDRESS as `0x${string}`),
};

// Known presets for adding chains to MetaMask
const PRESETS: Record<number, { chainName: string; explorer: string; symbol: string }> = {
  11155111: { chainName: "Sepolia",      explorer: "https://sepolia.etherscan.io",  symbol: "ETH" },
  84532:    { chainName: "Base Sepolia", explorer: "https://sepolia.basescan.org",  symbol: "ETH" },
};

// --- Minimal ABIs ---
const factoryAbi = [
  { type: "function", name: "recordOf", stateMutability: "view", inputs: [{ name: "owner", type: "address" }], outputs: [{ type: "address" }] },
  { type: "function", name: "createRecord", stateMutability: "nonpayable", inputs: [], outputs: [] },
] as const;

const patientRecordAbi = [
  { type: "function", name: "seq", stateMutability: "view", inputs: [], outputs: [{ type: "uint64" }] },
  { type: "function", name: "contentHashAt", stateMutability: "view", inputs: [{ type: "uint64" }], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "anchor", stateMutability: "nonpayable", inputs: [{ type: "bytes32" }, { type: "uint32" }], outputs: [] }, // uint32 l2Id
] as const;

// -------- Vault READ ABIs (per your vault) --------
const vaultReadAbi = [
  { type: "function", name: "getCiphertextByTag", stateMutability: "view", inputs: [{ type: "bytes16" }], outputs: [{ type: "bytes" }] },
  { type: "function", name: "getEnvelopeIdByTag", stateMutability: "view", inputs: [{ type: "bytes16" }], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "getCiphertext",      stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ type: "bytes" }] },
] as const;

// --- VIEM clients ---
const l1Public = createPublicClient({ chain: { id: env.l1Id } as any, transport: http(env.l1Url) });
const l2Public = createPublicClient({ chain: { id: env.l2Id } as any, transport: http(env.l2Url) });

function walletL1() {
  const eth = (window as any).ethereum;
  if (!eth) throw new Error("MetaMask not found");
  return createWalletClient({ chain: { id: env.l1Id } as any, transport: custom(eth) });
}
function walletL2() {
  const eth = (window as any).ethereum;
  if (!eth) throw new Error("MetaMask not found");
  return createWalletClient({ chain: { id: env.l2Id } as any, transport: custom(eth) });
}

async function ensureChain(targetId: number, rpcUrl?: string) {
  const eth = (window as any).ethereum;
  if (!eth) throw new Error("MetaMask not found");
  const curHex: string = await eth.request({ method: "eth_chainId" });
  const cur = parseInt(curHex, 16);
  if (cur === targetId) return;
  const chainIdHex = `0x${targetId.toString(16)}`;
  try {
    await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId: chainIdHex }] });
  } catch (e: any) {
    if (e?.code === 4902) {
      const p = PRESETS[targetId] || { chainName: `Chain ${targetId}`, explorer: "", symbol: "ETH" };
      await eth.request({
        method: "wallet_addEthereumChain",
        params: [{ chainId: chainIdHex, chainName: p.chainName, rpcUrls: rpcUrl ? [rpcUrl] : [""], nativeCurrency: { name: p.symbol, symbol: p.symbol, decimals: 18 }, blockExplorerUrls: p.explorer ? [p.explorer] : [] }],
      });
      await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId: chainIdHex }] });
    } else {
      throw e;
    }
  }
}

// --- Crypto helpers ---
const enc = new TextEncoder();
const dec = new TextDecoder();

function concatBytes(...arrs: Uint8Array[]) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) out.set(a, off), (off += a.length);
  return out;
}

function u64be(n: number) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), false);
  return b;
}

// Small helpers
function downloadBytes(bytes: Uint8Array, filename: string, mime = "application/octet-stream") {
  const blob = new Blob([bytes], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
function shortAddr(a: string) {
  return `${a.slice(0, 6)}…${a.slice(-4)}`;
}

// -------- Wallet-bound secret derivation (OFF-CHAIN signature) --------
async function deriveRootViaSignature(recordAddr: Hex): Promise<Uint8Array> {
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

// A) Preferred: index-based (no plaintext hash used)
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

// B) Compat: root + contentHash (for mid-era entries)
async function deriveTagKeyNonceFromRootContentHash(
  root: Uint8Array,
  recordAddr: Hex,
  contentHash: Uint8Array
) {
  const base = concatBytes(enc.encode("PC-DERIVE-ROOT-CH"), root, hexToBytes(recordAddr), contentHash);
  const tag   = (await sha256Bytes(concatBytes(enc.encode("TAG"), base))).slice(0, 16);
  const key   =  await sha256Bytes(concatBytes(enc.encode("KEY"), base));
  const nonce = (await sha256Bytes(concatBytes(enc.encode("NONCE"), base))).slice(0, 12);
  return { tagHex: toHex(tag) as Hex, keyBytes: key, nonce };
}

// C) Legacy: public + contentHash (oldest entries)
async function deriveTagKeyNonce_Legacy(
  account: Hex,
  recordAddr: Hex,
  contentHash: Uint8Array
) {
  const base = concatBytes(enc.encode("PC-DERIVE"), hexToBytes(account), hexToBytes(recordAddr), contentHash);
  const tag   = (await sha256Bytes(concatBytes(enc.encode("TAG"), base))).slice(0, 16);
  const key   =  await sha256Bytes(concatBytes(enc.encode("KEY"), base));
  const nonce = (await sha256Bytes(concatBytes(enc.encode("NONCE"), base))).slice(0, 12);
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

// Read ciphertext by tag via your vault API
async function fetchCiphertextByTag(tagHex: Hex): Promise<Hex | null> {
  const vault = getContract({ address: env.vault as `0x${string}`, abi: vaultReadAbi as any, client: l2Public });
  try {
    const bytesByTag = (await (vault as any).read.getCiphertextByTag([tagHex])) as Hex;
    if (bytesByTag && bytesByTag !== "0x") return bytesByTag;
  } catch {}
  try {
    const envId = (await (vault as any).read.getEnvelopeIdByTag([tagHex])) as Hex;
    if (envId && envId !== "0x".padEnd(66, "0")) {
      const bytesById = (await (vault as any).read.getCiphertext([envId])) as Hex;
      if (bytesById && bytesById !== "0x") return bytesById;
    }
  } catch {}
  return null;
}

// ---------- Auto-detect vault write shape (args & return) ----------
const ABI_CT_TAG_NORET = [
  { type: "function", name: "put", stateMutability: "nonpayable",
    inputs: [{ name: "ciphertext", type: "bytes" }, { name: "tag", type: "bytes16" }], outputs: [] },
] as const;
const ABI_TAG_CT_NORET = [
  { type: "function", name: "put", stateMutability: "nonpayable",
    inputs: [{ name: "tag", type: "bytes16" }, { name: "ciphertext", type: "bytes" }], outputs: [] },
] as const;
const ABI_CT_TAG_RET   = [
  { type: "function", name: "put", stateMutability: "nonpayable",
    inputs: [{ name: "ciphertext", type: "bytes" }, { name: "tag", type: "bytes16" }], outputs: [{ type: "bytes32" }] },
] as const;
const ABI_TAG_CT_RET   = [
  { type: "function", name: "put", stateMutability: "nonpayable",
    inputs: [{ name: "tag", type: "bytes16" }, { name: "ciphertext", type: "bytes" }], outputs: [{ type: "bytes32" }] },
] as const;

type PutVariant = "ct,tag (no-ret)" | "tag,ct (no-ret)" | "ct,tag (returns)" | "tag,ct (returns)";

async function simulatePutAuto(from: Hex, ctHex: Hex, tagHex: Hex) {
  const candidates: Array<{ abi: any; args: [Hex, Hex]; label: PutVariant }> = [
    { abi: ABI_CT_TAG_NORET, args: [ctHex, tagHex], label: "ct,tag (no-ret)" },
    { abi: ABI_TAG_CT_NORET, args: [tagHex, ctHex], label: "tag,ct (no-ret)" },
    { abi: ABI_CT_TAG_RET,   args: [ctHex, tagHex], label: "ct,tag (returns)" },
    { abi: ABI_TAG_CT_RET,   args: [tagHex, ctHex], label: "tag,ct (returns)" },
  ];
  const errors: string[] = [];
  for (const c of candidates) {
    try {
      const { request } = await l2Public.simulateContract({
        address: env.vault as `0x${string}`,
        abi: c.abi,
        functionName: "put",
        args: c.args,
        account: from,
      });
      return { request, label: c.label };
    } catch (e: any) {
      errors.push(`${c.label}: ${e?.shortMessage || e?.message || String(e)}`);
    }
  }
  throw new Error("All put() variants failed:\n" + errors.join("\n"));
}

export default function App() {
  const [account, setAccount] = useState<Hex>("0x0000000000000000000000000000000000000000");
  const [recordAddr, setRecord] = useState<Hex>("0x0000000000000000000000000000000000000000");
  const [status, setStatus] = useState<string>("");
  const [didAnchor, setDidAnchor] = useState<boolean>(false);
  const [didStore, setDidStore] = useState<boolean>(false);
  const [jsonText, setJson] = useState<string>('{"resourceType":"Bundle","type":"collection","entry":[{"resource":{"resourceType":"Patient","id":"me"}}]}');
  const [hashHex, setHashHex] = useState<string>("");
  const [l2Tag, setL2Tag] = useState<string>("");
  const [lastTx, setLastTx] = useState<string>("");

  // Wallet-bound root (in-memory)
  const [root, setRoot] = useState<Uint8Array | null>(null);

  // Restore state
  const [restoreResults, setRestoreResults] = useState<RestoreRow[]>([]);

  async function connect() {
    const eth = (window as any).ethereum;
    if (!eth) { alert("MetaMask not found"); return; }
    const [addr] = await eth.request({ method: "eth_requestAccounts" });
    setAccount(addr);
  }

  // Robust + diagnostic ensureRecord
  async function ensureRecord() {
    if (!account || account === "0x0000000000000000000000000000000000000000") {
      alert("Connect MetaMask first");
      return;
    }
    if (!/^0x[0-9a-fA-F]{40}$/.test(env.factory || "")) {
      setStatus("❌ VITE_FACTORY_ADDRESS is missing or invalid.");
      return;
    }
    try {
      setStatus("Switching to L1 & checking your PatientRecord…");
      await ensureChain(env.l1Id, env.l1Url);

      // verify wallet really switched
      const eth = (window as any).ethereum;
      const curHex: string = await eth.request({ method: "eth_chainId" });
      const cur = parseInt(curHex, 16);
      if (cur !== env.l1Id) throw new Error(`Wallet is on chainId ${cur} but expected ${env.l1Id}`);

      // ping L1 RPC
      await l1Public.getBlockNumber();

      const factory = getContract({ address: env.factory, abi: factoryAbi, client: l1Public });

      // read recordOf
      let rec: Hex;
      try {
        rec = (await factory.read.recordOf([account])) as Hex;
      } catch (e: any) {
        throw new Error("factory.recordOf failed — check VITE_L1_RPC_URL / VITE_FACTORY_ADDRESS. " + (e?.shortMessage || e?.message || String(e)));
      }

      if (!rec || rec === "0x0000000000000000000000000000000000000000") {
        const w = walletL1();
        const [from] = await w.getAddresses();

        let request;
        try {
          ({ request } = await l1Public.simulateContract({
            address: env.factory, abi: factoryAbi, functionName: "createRecord", account: from,
          }));
        } catch (e: any) {
          throw new Error("simulate createRecord failed — is the factory ABI/address correct? " + (e?.shortMessage || e?.message || String(e)));
        }

        setStatus("Requesting wallet confirmation to create record…");
        const txHash = await w.writeContract(request);
        setLastTx(txHash as string);

        setStatus("Tx sent — waiting for 1 confirmation…");
        await l1Public.waitForTransactionReceipt({ hash: txHash, confirmations: 1 });

        rec = (await factory.read.recordOf([account])) as Hex;
        if (!rec || rec === "0x0000000000000000000000000000000000000000") {
          throw new Error("Record still zero address after create — did the transaction succeed on the correct chain?");
        }
      }

      setRecord(rec);
      setStatus(`✅ Record ready: ${rec}`);
    } catch (e: any) {
      console.error("ensureRecord error", e);
      const msg = e?.shortMessage || e?.message || String(e);
      setStatus("❌ L1 check/create failed: " + msg);
    }
  }

  function canonicalBytesFromJson(text: string): Uint8Array {
    const obj = JSON.parse(text);
    return enc.encode(stringify(obj, { space: 0 }));
  }

  async function authorizeKeyDerivation() {
    try {
      if (!recordAddr || recordAddr === "0x0000000000000000000000000000000000000000") {
        return alert("Ensure your record first");
      }
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
      if (!recordAddr || recordAddr === "0x0000000000000000000000000000000000000000") {
        return alert("Ensure your record first");
      }
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
      const { request } = await l1Public.simulateContract({
        address: recordAddr, abi: patientRecordAbi, functionName: "anchor", args: [hex as Hex, env.l2Id], account: from,
      });

      setStatus("Requesting wallet confirmation…");
      const txHash = await w.writeContract(request);
      setLastTx(txHash as string);

      setStatus("Tx sent — waiting for 1 confirmation…");
      await l1Public.waitForTransactionReceipt({ hash: txHash, confirmations: 1 });
      setDidAnchor(true);
      setStatus("✅ Anchored on L1. You can now Encrypt & Store on L2.");
      document.getElementById("quick-actions")?.scrollIntoView({ behavior: "smooth", block: "center" });
    } catch (e: any) {
      console.error("anchor error", e);
      setStatus("❌ L1 anchor failed: " + (e?.shortMessage || e?.message || String(e)));
    }
  }

  async function encryptAndStoreL2() {
    try {
      if (!account || account === "0x0000000000000000000000000000000000000000") return alert("Connect MetaMask first");
      if (!recordAddr || recordAddr === "0x0000000000000000000000000000000000000000") return alert("Ensure your record first");
      if (!root) return alert("Click “Authorize key derivation (sign)” first.");

      setStatus("Switching to L2…");
      await ensureChain(env.l2Id, env.l2Url);

      // Determine index i for this snapshot = current L1 seq + 1
      const rec = getContract({ address: recordAddr, abi: patientRecordAbi, client: l1Public });
      const seq = Number(await rec.read.seq());
      const iNext = seq + 1;

      setStatus(`Encrypting snapshot #${iNext} and storing on L2…`);

      const { tagHex, keyBytes, nonce } = await deriveTagKeyNonceFromRootIndex(root!, recordAddr, iNext);
      const canonical = canonicalBytesFromJson(jsonText);
      const ciphertext = await aesGcmEncrypt(keyBytes, nonce, canonical);
      const ctHex = toHex(ciphertext);
      setL2Tag(tagHex);

      const w = walletL2();
      const [from] = await w.getAddresses();

      // Auto-detect put() shape
      setStatus("Detecting vault put() shape…");
      const { request, label } = await simulatePutAuto(from, ctHex as Hex, tagHex as Hex);

      setStatus(`Requesting wallet confirmation (using ${label})…`);
      const txHash = await w.writeContract(request);
      setLastTx(txHash as string);

      setStatus("Tx sent — waiting for L2 confirmation…");
      await l2Public.waitForTransactionReceipt({ hash: txHash, confirmations: 1 });
      setDidStore(true);
      setStatus(`✅ Stored snapshot #${iNext} on L2 via ${label}. You may anchor on L1 now or later.`);
      document.getElementById("quick-actions")?.scrollIntoView({ behavior: "smooth", block: "center" });
    } catch (e: any) {
      console.error("l2 store error", e);
      setStatus("❌ L2 store failed: " + (e?.shortMessage || e?.message || String(e)));
    }
  }

  async function restoreFromWallet() {
    try {
      if (!recordAddr || recordAddr === "0x0000000000000000000000000000000000000000") return alert("Ensure your record first");
      if (!root) return alert("Click “Authorize key derivation (sign)” first.");
      setStatus("Restoring with wallet-bound derivation…");

      const rec = getContract({ address: recordAddr, abi: patientRecordAbi, client: l1Public });
      const seq = Number(await rec.read.seq());

      // Detect 1-indexed vs 0-indexed (most PatientRecord impls are 1-indexed)
      const indices: number[] = [];
      try { await rec.read.contentHashAt([1n]); for (let i = 1; i <= seq; i++) indices.push(i); }
      catch { for (let i = 0; i < seq; i++) indices.push(i); }

      const out: RestoreRow[] = [];

      for (const i of indices) {
        const chHex = (await rec.read.contentHashAt([BigInt(i)])) as Hex; // used ONLY after decrypt to verify
        const chBytes = hexToBytes(chHex);

        let triedTag: Hex | null = null;
        let pt: Uint8Array | null = null;
        let mode: "root-index" | "root-ch" | "legacy" | undefined;

        // A) root + index (preferred)
        {
          const d = await deriveTagKeyNonceFromRootIndex(root!, recordAddr, i);
          triedTag = d.tagHex as Hex;
          const ctHex = await fetchCiphertextByTag(triedTag);
          if (ctHex && ctHex !== "0x") {
            try { pt = await aesGcmDecrypt(d.keyBytes, d.nonce, hexToBytes(ctHex)); mode = "root-index"; } catch {}
          }
        }

        // B) root + contentHash (compat)
        if (!pt) {
          const d = await deriveTagKeyNonceFromRootContentHash(root!, recordAddr, chBytes);
          triedTag = d.tagHex as Hex;
          const ctHex = await fetchCiphertextByTag(triedTag);
          if (ctHex && ctHex !== "0x") {
            try { pt = await aesGcmDecrypt(d.keyBytes, d.nonce, hexToBytes(ctHex)); mode = "root-ch"; } catch {}
          }
        }

        // C) legacy public + contentHash (oldest)
        if (!pt) {
          const d = await deriveTagKeyNonce_Legacy(account, recordAddr, chBytes);
          triedTag = d.tagHex as Hex;
          const ctHex = await fetchCiphertextByTag(triedTag);
          if (ctHex && ctHex !== "0x") {
            try { pt = await aesGcmDecrypt(d.keyBytes, d.nonce, hexToBytes(ctHex)); mode = "legacy"; } catch {}
          }
        }

        if (!pt) { out.push({ i, ok: false, tag: triedTag || "0x", ch: chHex, missing: true }); continue; }

        // Verify AFTER decrypt: sha256(plaintext) must equal L1 contentHashAt(i)
        const check = await sha256Bytes(pt);
        const ok = toHex(check).toLowerCase() === (chHex as string).toLowerCase();

        let preview: string | undefined;
        try {
          const j = JSON.parse(dec.decode(pt));
          const s = JSON.stringify(j);
          preview = s.slice(0, 140) + (s.length > 140 ? "…" : "");
        } catch {}
        out.push({ i, ok, tag: triedTag!, ch: chHex, preview, mode });
      }

      setRestoreResults(out);
      const okCount = out.filter((r) => r.ok).length;
      setStatus(`✅ Restore complete (${okCount}/${out.length} verified)`);
    } catch (e: any) {
      console.error("restore error", e);
      setStatus("❌ Restore failed: " + (e?.shortMessage || e?.message || String(e)));
    }
  }

  // --- Per-entry downloads ---
  async function onDownloadCipher(r: RestoreRow) {
    try {
      const ctHex = await fetchCiphertextByTag(r.tag as Hex);
      if (!ctHex) return alert("Ciphertext not found in vault for this tag.");
      const fn = `record-${shortAddr(String(recordAddr))}-#${r.i}-${(r.ch as string).slice(2, 10)}.cipher.bin`;
      downloadBytes(hexToBytes(ctHex), fn);
    } catch (e: any) {
      alert("Download failed: " + (e?.shortMessage || e?.message || String(e)));
    }
  }

  async function onDownloadDecrypted(r: RestoreRow) {
    try {
      let keyBytes: Uint8Array, nonce: Uint8Array;

      if (r.mode === "legacy") {
        ({ keyBytes, nonce } = await deriveTagKeyNonce_Legacy(account, recordAddr, hexToBytes(r.ch as Hex)));
      } else if (r.mode === "root-ch") {
        if (!root) return alert("Click “Authorize key derivation (sign)” first.");
        ({ keyBytes, nonce } = await deriveTagKeyNonceFromRootContentHash(root!, recordAddr, hexToBytes(r.ch as Hex)));
      } else {
        if (!root) return alert("Click “Authorize key derivation (sign)” first.");
        ({ keyBytes, nonce } = await deriveTagKeyNonceFromRootIndex(root!, recordAddr, r.i));
      }

      const ctHex = await fetchCiphertextByTag(r.tag as Hex);
      if (!ctHex) return alert("Ciphertext not found in vault for this tag.");

      const pt = await aesGcmDecrypt(keyBytes, nonce, hexToBytes(ctHex));
      const digest = await sha256Bytes(pt);
      const ok = toHex(digest).toLowerCase() === (r.ch as string).toLowerCase();
      if (!ok) return alert("Hash mismatch — refusing to export plaintext.");

      const fn = `record-${shortAddr(String(recordAddr))}-#${r.i}-${(r.ch as string).slice(2, 10)}.fhir.json`;
      downloadBytes(pt, fn, "application/fhir+json");
    } catch (e: any) {
      alert("Download failed: " + (e?.shortMessage || e?.message || String(e)));
    }
  }

  return (
    <div style={{ padding: 24, fontFamily: "system-ui, sans-serif", maxWidth: 900, margin: "0 auto" }}>
      <h1>Prometheus’ Chains — Patient Web MVP</h1>

      <div style={{ marginBottom: 12 }}>
        <button onClick={connect}>Connect Wallet</button>{" "}
        <button onClick={ensureRecord}>Check / Create L1 PatientRecord</button>{" "}
        <button onClick={authorizeKeyDerivation} disabled={!recordAddr || recordAddr.endsWith("0000")}>
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
        We derive tag/key/nonce from your wallet secret (off-chain) + record (+ index or content hash for compat), fetch ciphertext, decrypt locally, then verify against L1.
      </p>
      <div style={{ marginTop: 8 }}>
        <button onClick={restoreFromWallet}>Restore timeline</button>
      </div>

      {restoreResults.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <b>Restored entries:</b>
          <ul>
            {restoreResults.map((r: RestoreRow) => (
              <li key={r.i} style={{ margin: "6px 0" }}>
                #{r.i} — tag {r.tag} — {r.ok ? "✅ verified" : r.missing ? "⚠️ missing on L2" : "❌ hash mismatch"}
                {r.mode === "legacy" ? (
                  <span style={{ opacity: 0.6 }}> (legacy)</span>
                ) : r.mode === "root-ch" ? (
                  <span style={{ opacity: 0.6 }}> (wallet+contentHash)</span>
                ) : r.mode === "root-index" ? (
                  <span style={{ opacity: 0.6 }}> (wallet+index)</span>
                ) : null}
                {r.preview && (
                  <div style={{ fontSize: 12, opacity: 0.8, wordBreak: "break-all" }}>preview: {r.preview}</div>
                )}
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

      {/* Quick Actions */}
      <div
        id="quick-actions"
        style={{
          marginTop: 8,
          padding: 12,
          borderRadius: 12,
          border: "1px solid rgba(0,0,0,0.1)",
          background: "linear-gradient(180deg, rgba(0,0,0,0.03), rgba(0,0,0,0.01))",
        }}
      >
        <b>Quick actions</b>
        <div style={{ marginTop: 8 }}>
          <button onClick={encryptAndStoreL2}>
            {didStore ? "Re-encrypt & Store to L2" : "Encrypt & Store to L2 (Next)"}
          </button>{" "}
          <button onClick={hashAndAnchorL1}>
            {didAnchor ? "Re-anchor on L1" : "Generate Hash & Anchor to L1"}
          </button>
        </div>
        <div style={{ fontSize: 12, opacity: 0.75, marginTop: 6 }}>
          Order tip: You can store on L2 first and anchor after, or anchor first and store next — verification works either way.
        </div>
      </div>
    </div>
  );
}
