import { useState } from "react";
import {
  createPublicClient,
  createWalletClient,
  getContract,
  custom,
  http,
  toHex,
  hexToBytes,
  parseAbiItem,
} from "viem";
import type { Hex } from "viem";
import stringify from "json-stable-stringify";
import { hash as sha256Bytes } from "./lib/sdk/crypto/hash"; // local helper (Uint8Array sha256)

// ------- Types -------
type RestoreRow = {
  i: number;
  ok: boolean;
  tag: string;
  ch: string;
  preview?: string;
  missing?: boolean;
};

// --- ENV from Vite (set these in Vercel/local .env) ---
const env = {
  l1Id: Number(import.meta.env.VITE_L1_CHAIN_ID), // e.g. 11155111 (Sepolia)
  l1Url: import.meta.env.VITE_L1_RPC_URL as string,
  l2Id: Number(import.meta.env.VITE_L2_CHAIN_ID), // e.g. 84532 (Base Sepolia)
  l2Url: import.meta.env.VITE_L2_RPC_URL as string,
  factory: import.meta.env.VITE_FACTORY_ADDRESS as `0x${string}`,
  vault: import.meta.env.VITE_VAULT_ADDRESS as `0x${string}`,
};

// Known presets to help add chains if missing in MetaMask.
const PRESETS: Record<number, { chainName: string; explorer: string; symbol: string }> = {
  11155111: {
    chainName: "Sepolia",
    explorer: "https://sepolia.etherscan.io",
    symbol: "ETH",
  },
  84532: {
    chainName: "Base Sepolia",
    explorer: "https://sepolia.basescan.org",
    symbol: "ETH",
  },
};

// --- Minimal ABIs ---
const factoryAbi = [
  {
    type: "function",
    name: "recordOf",
    stateMutability: "view",
    inputs: [{ name: "owner", type: "address" }],
    outputs: [{ type: "address" }],
  },
  {
    type: "function",
    name: "createRecord",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
] as const;

const patientRecordAbi = [
  { type: "function", name: "seq", stateMutability: "view", inputs: [], outputs: [{ type: "uint64" }] },
  {
    type: "function",
    name: "contentHashAt",
    stateMutability: "view",
    inputs: [{ type: "uint64" }],
    outputs: [{ type: "bytes32" }],
  },
  {
    type: "function",
    name: "anchor",
    stateMutability: "nonpayable",
    // IMPORTANT: uint32 (not uint256)
    inputs: [{ type: "bytes32" }, { type: "uint32" }],
    outputs: [],
  },
] as const;

// EventVault (hash-addressed ciphertext storage)
// NOTE: Adjust `bytes16` to `bytes32` if your deployed vault expects 32-byte tags.
const vaultWriteAbi = [
  {
    type: "function",
    name: "put",
    stateMutability: "nonpayable",
    inputs: [
      { name: "tag", type: "bytes16" },
      { name: "ciphertext", type: "bytes" },
    ],
    outputs: [],
  },
] as const;

// Optional read shapes (support both variants if present on your deployed contract)
const vaultReadAbi = [
  { type: "function", name: "get", stateMutability: "view", inputs: [{ type: "bytes16" }], outputs: [{ type: "bytes" }] },
  { type: "function", name: "blobs", stateMutability: "view", inputs: [{ type: "bytes16" }], outputs: [{ type: "bytes" }] },
] as const;

// Event for log-based recovery (if contract emits ciphertext)
const StoredEvent = parseAbiItem("event Stored(bytes16 tag, bytes ciphertext)");

// --- VIEM public + wallet clients ---
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
    // 4902: Unrecognized chain — add it
    if (e?.code === 4902) {
      const p = PRESETS[targetId] || { chainName: `Chain ${targetId}`, explorer: "", symbol: "ETH" };
      await eth.request({
        method: "wallet_addEthereumChain",
        params: [
          {
            chainId: chainIdHex,
            chainName: p.chainName,
            rpcUrls: rpcUrl ? [rpcUrl] : [""],
            nativeCurrency: { name: p.symbol, symbol: p.symbol, decimals: 18 },
            blockExplorerUrls: p.explorer ? [p.explorer] : [],
          },
        ],
      });
      // Try switch again
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

// Derivation used for L2 store (account-bound) — retained for backward compatibility
async function deriveTagKeyNonce(
  account: Hex,
  recordAddr: Hex,
  contentHash: Uint8Array
): Promise<{ tagHex: Hex; keyBytes: Uint8Array; nonce: Uint8Array }> {
  const base = concatBytes(enc.encode("PC-DERIVE"), hexToBytes(account), hexToBytes(recordAddr), contentHash);
  const tag = (await sha256Bytes(concatBytes(enc.encode("TAG"), base))).slice(0, 16); // 16 bytes
  const key = await sha256Bytes(concatBytes(enc.encode("KEY"), base)); // 32 bytes
  const nonce = (await sha256Bytes(concatBytes(enc.encode("NONCE"), base))).slice(0, 12); // 12 bytes
  return { tagHex: toHex(tag) as Hex, keyBytes: key, nonce };
}

// Seed-based derivation for restore (mnemonic/passphrase never leaves device)
async function deriveTagKeyNonceFromSeed(
  seed: string,
  recordAddr: Hex,
  contentHash: Uint8Array
): Promise<{ tagHex: Hex; keyBytes: Uint8Array; nonce: Uint8Array }> {
  const seedRoot = await sha256Bytes(enc.encode(seed.trim())); // simple root; swap for HKDF/BIP39 if desired
  const base = concatBytes(enc.encode("PC-DERIVE-SEED"), seedRoot, hexToBytes(recordAddr), contentHash);
  const tag = (await sha256Bytes(concatBytes(enc.encode("TAG"), base))).slice(0, 16);
  const key = await sha256Bytes(concatBytes(enc.encode("KEY"), base));
  const nonce = (await sha256Bytes(concatBytes(enc.encode("NONCE"), base))).slice(0, 12);
  return { tagHex: toHex(tag) as Hex, keyBytes: key, nonce };
}

async function aesGcmEncrypt(keyBytes: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plaintext);
  return new Uint8Array(ct);
}

async function aesGcmDecrypt(keyBytes: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ciphertext);
  return new Uint8Array(pt);
}

// Try multiple read paths to fetch ciphertext by tag from the L2 vault
async function fetchCiphertextByTag(tagHex: Hex): Promise<Hex | null> {
  const vaultRead = getContract({ address: env.vault, abi: vaultReadAbi as any, client: l2Public });
  // 1) Direct getter `get(tag)`
  try {
    const res = (await (vaultRead as any).read.get([tagHex])) as Hex;
    if (res && res !== "0x") return res;
  } catch {}
  // 2) Public mapping `blobs(tag)`
  try {
    const res2 = (await (vaultRead as any).read.blobs([tagHex])) as Hex;
    if (res2 && res2 !== "0x") return res2;
  } catch {}
  // 3) Logs: event Stored(tag, ciphertext)
  try {
    const logs = await l2Public.getLogs({
      address: env.vault,
      event: StoredEvent,
      args: { tag: tagHex },
      fromBlock: 0n,
      toBlock: "latest",
    });
    if (logs.length) {
      const last = logs[logs.length - 1] as any;
      const ct: Hex | undefined = last?.args?.ciphertext;
      if (ct && ct !== "0x") return ct;
    }
  } catch {}
  return null;
}

export default function App() {
  const [account, setAccount] = useState<Hex>("0x0000000000000000000000000000000000000000");
  const [recordAddr, setRecord] = useState<Hex>("0x0000000000000000000000000000000000000000");
  const [status, setStatus] = useState<string>("");
  const [didAnchor, setDidAnchor] = useState<boolean>(false);
  const [didStore, setDidStore] = useState<boolean>(false);
  const [jsonText, setJson] = useState<string>(
    '{"resourceType":"Bundle","type":"collection","entry":[{"resource":{"resourceType":"Patient","id":"me"}}]}'
  );
  const [hashHex, setHashHex] = useState<string>("");
  const [l2Tag, setL2Tag] = useState<string>("");
  const [lastTx, setLastTx] = useState<string>("");

  // Restore state
  const [seed, setSeed] = useState<string>("");
  const [restoreResults, setRestoreResults] = useState<RestoreRow[]>([]);

  async function connect() {
    const eth = (window as any).ethereum;
    if (!eth) {
      alert("MetaMask not found");
      return;
    }
    const [addr] = await eth.request({ method: "eth_requestAccounts" });
    setAccount(addr);
  }

  async function ensureRecord() {
    if (!account || account === "0x0000000000000000000000000000000000000000") {
      return alert("Connect MetaMask first");
    }
    await ensureChain(env.l1Id, env.l1Url);
    setStatus("Checking/creating your L1 PatientRecord…");

    const factory = getContract({ address: env.factory, abi: factoryAbi, client: l1Public });
    let rec = (await factory.read.recordOf([account])) as Hex;

    if (rec === "0x0000000000000000000000000000000000000000") {
      const w = walletL1();
      const [from] = await w.getAddresses();
      const { request } = await l1Public.simulateContract({
        address: env.factory,
        abi: factoryAbi,
        functionName: "createRecord",
        account: from,
      });
      const txHash = await w.writeContract(request);
      setStatus("Tx sent to create record — waiting for confirmation…");
      setLastTx(txHash as string);
      await l1Public.waitForTransactionReceipt({ hash: txHash, confirmations: 1 });
      rec = (await factory.read.recordOf([account])) as Hex;
    }
    setRecord(rec);
    setStatus(`✅ Record ready: ${rec}`);
  }

  function canonicalBytesFromJson(text: string): Uint8Array {
    const obj = JSON.parse(text);
    return enc.encode(stringify(obj, { space: 0 }));
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

      // Preflight to surface ABI/arg errors immediately
      setStatus("Preflighting anchor call…");
      const { request } = await l1Public.simulateContract({
        address: recordAddr,
        abi: patientRecordAbi,
        functionName: "anchor",
        args: [hex as Hex, env.l2Id], // uint32 -> number
        account: from,
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
      setStatus("Switching to L2…");
      await ensureChain(env.l2Id, env.l2Url);
      setStatus("Encrypting and storing ciphertext on L2…");

      // Canonicalize & hash (for deterministic derivation)
      const canonical = canonicalBytesFromJson(jsonText);
      const digest = await sha256Bytes(canonical); // 32 bytes
      const { tagHex, keyBytes, nonce } = await deriveTagKeyNonce(account, recordAddr, digest);

      const ciphertext = await aesGcmEncrypt(keyBytes, nonce, canonical);
      const ctHex = toHex(ciphertext);

      const w = walletL2();
      const [from] = await w.getAddresses();

      // Preflight
      const { request } = await l2Public.simulateContract({
        address: env.vault,
        abi: vaultWriteAbi,
        functionName: "put",
        args: [tagHex as Hex, ctHex as Hex],
        account: from,
      });

      const txHash = await w.writeContract(request);
      setLastTx(txHash as string);
      setStatus("Tx sent — waiting for L2 confirmation…");
      await l2Public.waitForTransactionReceipt({ hash: txHash, confirmations: 1 });
      setL2Tag(tagHex);
      setDidStore(true);
      setStatus("✅ Stored on L2 (ciphertext vault). Optional: re-run Anchor to link this snapshot explicitly.");
      document.getElementById("quick-actions")?.scrollIntoView({ behavior: "smooth", block: "center" });
    } catch (e: any) {
      console.error("l2 store error", e);
      setStatus("❌ L2 store failed: " + (e?.shortMessage || e?.message || String(e)));
    }
  }

  async function restoreFromSeed() {
    try {
      if (!seed.trim()) return alert("Enter your restore seed (mnemonic/passphrase)");
      if (!recordAddr || recordAddr === "0x0000000000000000000000000000000000000000") return alert("Ensure your record first");
      setStatus("Restoring from seed…");

      // Read timeline from L1
      const rec = getContract({ address: recordAddr, abi: patientRecordAbi, client: l1Public });
      const seq = Number(await rec.read.seq());
      const out: RestoreRow[] = [];

      for (let i = 0; i < seq; i++) {
        const chHex = (await rec.read.contentHashAt([BigInt(i)])) as Hex;
        const chBytes = hexToBytes(chHex);
        // Derive tag/key/nonce from seed + record + contentHash
        const { tagHex, keyBytes, nonce } = await deriveTagKeyNonceFromSeed(seed, recordAddr, chBytes);
        // Fetch ciphertext by tag from L2 (read / logs)
        const ctHex = await fetchCiphertextByTag(tagHex as Hex);
        if (!ctHex) {
          out.push({ i, ok: false, tag: tagHex, ch: chHex, missing: true });
          continue;
        }
        const pt = await aesGcmDecrypt(keyBytes, nonce, hexToBytes(ctHex as Hex));
        const check = await sha256Bytes(pt);
        const ok = toHex(check).toLowerCase() === (chHex as string).toLowerCase();
        let preview: string | undefined = undefined;
        try {
          const j = JSON.parse(dec.decode(pt));
          const s = JSON.stringify(j);
          preview = s.slice(0, 140) + (s.length > 140 ? "…" : "");
        } catch {}
        out.push({ i, ok, tag: tagHex, ch: chHex, preview });
      }

      setRestoreResults(out);
      const okCount = out.filter((r) => r.ok).length;
      setStatus(`✅ Restore complete (${okCount}/${out.length} verified)`);
    } catch (e: any) {
      console.error("restore error", e);
      setStatus("❌ Restore failed: " + (e?.shortMessage || e?.message || String(e)));
    }
  }

  return (
    <div style={{ padding: 24, fontFamily: "system-ui, sans-serif", maxWidth: 900, margin: "0 auto" }}>
      <h1>Prometheus’ Chains — Patient Web MVP</h1>

      <div style={{ marginBottom: 12 }}>
        <button onClick={connect}>Connect Wallet</button>{" "}
        <button onClick={ensureRecord}>Check / Create L1 PatientRecord</button>
      </div>

      <div style={{ opacity: 0.85, marginBottom: 16 }}>
        <div>
          <b>Account:</b> {account}
        </div>
        <div>
          <b>Record:</b> {recordAddr}
        </div>
        <div>
          <b>Env:</b> L1={env.l1Id} · L2={env.l2Id}
        </div>
      </div>

      <h3>Paste FHIR JSON (plaintext)</h3>
      <textarea rows={10} style={{ width: "100%" }} value={jsonText} onChange={(e) => setJson(e.target.value)} />

      <div style={{ marginTop: 12 }}>
        <button onClick={hashAndAnchorL1}>Generate Hash & Anchor to L1</button>{" "}
        <button onClick={encryptAndStoreL2}>Encrypt & Store to L2 Vault</button>
      </div>

      {hashHex && (
        <p style={{ marginTop: 8, wordBreak: "break-all" }}>
          <b>contentHash (L1):</b> {hashHex}
        </p>
      )}
      {l2Tag && (
        <p style={{ marginTop: 8, wordBreak: "break-all" }}>
          <b>tag (L2):</b> {l2Tag}
        </p>
      )}
      {lastTx && (
        <p style={{ marginTop: 8, wordBreak: "break-all" }}>
          <b>last tx:</b> {lastTx}
        </p>
      )}

      <hr style={{ margin: "24px 0" }} />

      <h3>Restore from seed</h3>
      <p style={{ opacity: 0.8, marginTop: -6 }}>
        Seed never leaves your device. We derive tags/keys per-entry and verify against L1 hashes.
      </p>
      <textarea
        rows={3}
        style={{ width: "100%" }}
        placeholder="Enter your seed (mnemonic or passphrase)"
        value={seed}
        onChange={(e) => setSeed(e.target.value)}
      />
      <div style={{ marginTop: 8 }}>
        <button onClick={restoreFromSeed}>Restore timeline</button>
      </div>

      {restoreResults.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <b>Restored entries:</b>
          <ul>
            {restoreResults.map((r: RestoreRow) => (
              <li key={r.i} style={{ margin: "6px 0" }}>
                #{r.i} — tag {r.tag} — {r.ok ? "✅ verified" : r.missing ? "⚠️ missing on L2" : "❌ hash mismatch"}
                {r.preview && (
                  <div style={{ fontSize: 12, opacity: 0.8, wordBreak: "break-all" }}>preview: {r.preview}</div>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      <p style={{ marginTop: 8 }}>{status}</p>

      {/* Quick Actions panel to avoid hunting for buttons */}
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
          Order tip: You can store on L2 first and anchor after, or anchor first and store next — hashes verify either
          way.
        </div>
      </div>
      <p style={{ opacity: 0.7, fontSize: 13, marginTop: 12 }}>
        Tip: If your deployed vault uses <code>bytes32</code> tags, update the ABI types (and derivation slice) accordingly.
      </p>
    </div>
  );
}
