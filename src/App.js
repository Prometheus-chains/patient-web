import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState } from "react";
import { createPublicClient, createWalletClient, getContract, custom, http, toHex, hexToBytes, } from "viem";
import stringify from "json-stable-stringify";
import { hash as sha256Bytes } from "./lib/sdk/crypto/hash"; // local helper (Uint8Array sha256)
// --- ENV from Vite (set these in Vercel/local .env) ---
const env = {
    l1Id: Number(import.meta.env.VITE_L1_CHAIN_ID), // e.g. 11155111 (Sepolia)
    l1Url: import.meta.env.VITE_L1_RPC_URL,
    l2Id: Number(import.meta.env.VITE_L2_CHAIN_ID), // e.g. 84532 (Base Sepolia)
    l2Url: import.meta.env.VITE_L2_RPC_URL,
    factory: import.meta.env.VITE_FACTORY_ADDRESS,
    vault: import.meta.env.VAULT_ADDRESS ?? import.meta.env.VITE_VAULT_ADDRESS,
};
// Known presets to help add chains if missing in MetaMask.
const PRESETS = {
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
];
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
];
// -------- Correct Vault ABIs (per your spec) --------
// Write: put(ciphertext, tag) -> returns envelopeId (bytes32)
const vaultWriteAbi = [
    {
        type: "function",
        name: "put",
        stateMutability: "nonpayable",
        inputs: [
            { name: "ciphertext", type: "bytes" }, // FIRST
            { name: "tag", type: "bytes16" } // SECOND
        ],
        outputs: [{ type: "bytes32" }], // envelopeId
    },
];
// Reads exposed by your vault
const vaultReadAbi = [
    { type: "function", name: "getCiphertextByTag", stateMutability: "view", inputs: [{ type: "bytes16" }], outputs: [{ type: "bytes" }] },
    { type: "function", name: "getEnvelopeIdByTag", stateMutability: "view", inputs: [{ type: "bytes16" }], outputs: [{ type: "bytes32" }] },
    { type: "function", name: "getCiphertext", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ type: "bytes" }] },
];
// --- VIEM public + wallet clients ---
const l1Public = createPublicClient({ chain: { id: env.l1Id }, transport: http(env.l1Url) });
const l2Public = createPublicClient({ chain: { id: env.l2Id }, transport: http(env.l2Url) });
function walletL1() {
    const eth = window.ethereum;
    if (!eth)
        throw new Error("MetaMask not found");
    return createWalletClient({ chain: { id: env.l1Id }, transport: custom(eth) });
}
function walletL2() {
    const eth = window.ethereum;
    if (!eth)
        throw new Error("MetaMask not found");
    return createWalletClient({ chain: { id: env.l2Id }, transport: custom(eth) });
}
async function ensureChain(targetId, rpcUrl) {
    const eth = window.ethereum;
    if (!eth)
        throw new Error("MetaMask not found");
    const curHex = await eth.request({ method: "eth_chainId" });
    const cur = parseInt(curHex, 16);
    if (cur === targetId)
        return;
    const chainIdHex = `0x${targetId.toString(16)}`;
    try {
        await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId: chainIdHex }] });
    }
    catch (e) {
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
        }
        else {
            throw e;
        }
    }
}
// --- Crypto helpers ---
const enc = new TextEncoder();
const dec = new TextDecoder();
function concatBytes(...arrs) {
    const total = arrs.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrs)
        out.set(a, off), (off += a.length);
    return out;
}
// Small helpers for download + filenames
function downloadBytes(bytes, filename, mime = "application/octet-stream") {
    const blob = new Blob([bytes], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}
function shortAddr(a) {
    return `${a.slice(0, 6)}…${a.slice(-4)}`;
}
// -------- Wallet-bound secret derivation (OFF-CHAIN signature) --------
// 1) Derive a stable per-record root from an EIP-712 signature (never on-chain).
async function deriveRootViaSignature(recordAddr) {
    const w = walletL1();
    const [from] = await w.getAddresses();
    const sig = await w.signTypedData({
        account: from,
        domain: {
            name: "PrometheusChains",
            version: "1",
            chainId: env.l1Id,
            verifyingContract: recordAddr,
        },
        types: {
            Derive: [
                { name: "purpose", type: "string" },
                { name: "record", type: "address" },
                { name: "l2", type: "uint256" },
            ],
        },
        primaryType: "Derive",
        message: {
            purpose: "pc-key-derivation-v1",
            record: recordAddr,
            l2: BigInt(env.l2Id),
        },
    });
    // Hash the signature bytes to get a 32-byte root
    return await sha256Bytes(hexToBytes(sig));
}
// 2) Use the root for per-entry derivation (tag/key/nonce).
async function deriveTagKeyNonceFromRoot(root, recordAddr, contentHash) {
    const base = concatBytes(enc.encode("PC-DERIVE-ROOT"), root, hexToBytes(recordAddr), contentHash);
    const tag = (await sha256Bytes(concatBytes(enc.encode("TAG"), base))).slice(0, 16);
    const key = await sha256Bytes(concatBytes(enc.encode("KEY"), base));
    const nonce = (await sha256Bytes(concatBytes(enc.encode("NONCE"), base))).slice(0, 12);
    return { tagHex: toHex(tag), keyBytes: key, nonce };
}
// 3) LEGACY (public-only) derivation retained for back-compat restore.
async function deriveTagKeyNonce_Legacy(account, recordAddr, contentHash) {
    const base = concatBytes(enc.encode("PC-DERIVE"), hexToBytes(account), hexToBytes(recordAddr), contentHash);
    const tag = (await sha256Bytes(concatBytes(enc.encode("TAG"), base))).slice(0, 16); // 16 bytes
    const key = await sha256Bytes(concatBytes(enc.encode("KEY"), base)); // 32 bytes
    const nonce = (await sha256Bytes(concatBytes(enc.encode("NONCE"), base))).slice(0, 12); // 12 bytes
    return { tagHex: toHex(tag), keyBytes: key, nonce };
}
async function aesGcmEncrypt(keyBytes, nonce, plaintext) {
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plaintext);
    return new Uint8Array(ct);
}
async function aesGcmDecrypt(keyBytes, nonce, ciphertext) {
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ciphertext);
    return new Uint8Array(pt);
}
// Read ciphertext by tag using your vault's API (no log scanning)
async function fetchCiphertextByTag(tagHex) {
    const vault = getContract({ address: env.vault, abi: vaultReadAbi, client: l2Public });
    // Fast path: direct convenience getter
    try {
        const bytesByTag = (await vault.read.getCiphertextByTag([tagHex]));
        if (bytesByTag && bytesByTag !== "0x")
            return bytesByTag;
    }
    catch { }
    // Fallback: resolve envelopeId, then fetch by id
    try {
        const envId = (await vault.read.getEnvelopeIdByTag([tagHex])); // bytes32
        if (envId && envId !== "0x0000000000000000000000000000000000000000000000000000000000000000") {
            const bytesById = (await vault.read.getCiphertext([envId]));
            if (bytesById && bytesById !== "0x")
                return bytesById;
        }
    }
    catch { }
    return null;
}
export default function App() {
    const [account, setAccount] = useState("0x0000000000000000000000000000000000000000");
    const [recordAddr, setRecord] = useState("0x0000000000000000000000000000000000000000");
    const [status, setStatus] = useState("");
    const [didAnchor, setDidAnchor] = useState(false);
    const [didStore, setDidStore] = useState(false);
    const [jsonText, setJson] = useState('{"resourceType":"Bundle","type":"collection","entry":[{"resource":{"resourceType":"Patient","id":"me"}}]}');
    const [hashHex, setHashHex] = useState("");
    const [l2Tag, setL2Tag] = useState("");
    const [lastTx, setLastTx] = useState("");
    // Wallet-bound root (in-memory only)
    const [root, setRoot] = useState(null);
    // Restore state
    const [restoreResults, setRestoreResults] = useState([]);
    async function connect() {
        const eth = window.ethereum;
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
        let rec = (await factory.read.recordOf([account]));
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
            setLastTx(txHash);
            await l1Public.waitForTransactionReceipt({ hash: txHash, confirmations: 1 });
            rec = (await factory.read.recordOf([account]));
        }
        setRecord(rec);
        setStatus(`✅ Record ready: ${rec}`);
    }
    function canonicalBytesFromJson(text) {
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
        }
        catch (e) {
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
            // Preflight to surface ABI/arg errors immediately
            setStatus("Preflighting anchor call…");
            const { request } = await l1Public.simulateContract({
                address: recordAddr,
                abi: patientRecordAbi,
                functionName: "anchor",
                args: [hex, env.l2Id], // uint32 -> number
                account: from,
            });
            setStatus("Requesting wallet confirmation…");
            const txHash = await w.writeContract(request);
            setLastTx(txHash);
            setStatus("Tx sent — waiting for 1 confirmation…");
            await l1Public.waitForTransactionReceipt({ hash: txHash, confirmations: 1 });
            setDidAnchor(true);
            setStatus("✅ Anchored on L1. You can now Encrypt & Store on L2.");
            document.getElementById("quick-actions")?.scrollIntoView({ behavior: "smooth", block: "center" });
        }
        catch (e) {
            console.error("anchor error", e);
            setStatus("❌ L1 anchor failed: " + (e?.shortMessage || e?.message || String(e)));
        }
    }
    async function encryptAndStoreL2() {
        try {
            if (!account || account === "0x0000000000000000000000000000000000000000")
                return alert("Connect MetaMask first");
            if (!recordAddr || recordAddr === "0x0000000000000000000000000000000000000000")
                return alert("Ensure your record first");
            if (!root)
                return alert("Click “Authorize key derivation (sign)” first.");
            setStatus("Switching to L2…");
            await ensureChain(env.l2Id, env.l2Url);
            setStatus("Encrypting and storing ciphertext on L2…");
            // Canonicalize & hash (for deterministic derivation)
            const canonical = canonicalBytesFromJson(jsonText);
            const digest = await sha256Bytes(canonical); // 32 bytes
            // NEW: secret, wallet-bound derivation
            const { tagHex, keyBytes, nonce } = await deriveTagKeyNonceFromRoot(root, recordAddr, digest);
            const ciphertext = await aesGcmEncrypt(keyBytes, nonce, canonical);
            const ctHex = toHex(ciphertext);
            const w = walletL2();
            const [from] = await w.getAddresses();
            // Preflight
            const { request } = await l2Public.simulateContract({
                address: env.vault,
                abi: vaultWriteAbi,
                functionName: "put",
                args: [ctHex, tagHex], // ciphertext FIRST, tag SECOND
                account: from,
            });
            const txHash = await w.writeContract(request);
            setLastTx(txHash);
            setStatus("Tx sent — waiting for L2 confirmation…");
            await l2Public.waitForTransactionReceipt({ hash: txHash, confirmations: 1 });
            setL2Tag(tagHex);
            setDidStore(true);
            setStatus("✅ Stored on L2 (ciphertext vault). Optional: re-run Anchor to link this snapshot explicitly.");
            document.getElementById("quick-actions")?.scrollIntoView({ behavior: "smooth", block: "center" });
        }
        catch (e) {
            console.error("l2 store error", e);
            setStatus("❌ L2 store failed: " + (e?.shortMessage || e?.message || String(e)));
        }
    }
    async function restoreFromWallet() {
        try {
            if (!recordAddr || recordAddr === "0x0000000000000000000000000000000000000000")
                return alert("Ensure your record first");
            if (!root)
                return alert("Click “Authorize key derivation (sign)” first.");
            setStatus("Restoring with wallet-bound derivation…");
            // Read timeline from L1
            const rec = getContract({ address: recordAddr, abi: patientRecordAbi, client: l1Public });
            const seq = Number(await rec.read.seq());
            // Auto-detect 1-indexed vs 0-indexed
            const indices = [];
            try {
                await rec.read.contentHashAt([1n]); // succeeds if 1-indexed
                for (let i = 1; i <= seq; i++)
                    indices.push(i);
            }
            catch {
                for (let i = 0; i < seq; i++)
                    indices.push(i);
            }
            const out = [];
            for (const i of indices) {
                const chHex = (await rec.read.contentHashAt([BigInt(i)]));
                const chBytes = hexToBytes(chHex);
                // Preferred: root derivation (secret)
                const rootDer = await deriveTagKeyNonceFromRoot(root, recordAddr, chBytes);
                let tagTried = rootDer.tagHex;
                let ctHex = await fetchCiphertextByTag(tagTried);
                let mode = undefined;
                let pt = null;
                if (ctHex && ctHex !== "0x") {
                    try {
                        pt = await aesGcmDecrypt(rootDer.keyBytes, rootDer.nonce, hexToBytes(ctHex));
                        mode = "root";
                    }
                    catch { }
                }
                // Legacy fallback (old entries created with public-only derivation)
                if (!pt) {
                    const legacyDer = await deriveTagKeyNonce_Legacy(account, recordAddr, chBytes);
                    tagTried = legacyDer.tagHex;
                    ctHex = await fetchCiphertextByTag(tagTried);
                    if (ctHex && ctHex !== "0x") {
                        try {
                            pt = await aesGcmDecrypt(legacyDer.keyBytes, legacyDer.nonce, hexToBytes(ctHex));
                            mode = "legacy";
                        }
                        catch { }
                    }
                }
                if (!pt) {
                    out.push({ i, ok: false, tag: tagTried, ch: chHex, missing: true });
                    continue;
                }
                // Verify against L1 contentHash
                const check = await sha256Bytes(pt);
                const ok = toHex(check).toLowerCase() === chHex.toLowerCase();
                let preview = undefined;
                try {
                    const j = JSON.parse(dec.decode(pt));
                    const s = JSON.stringify(j);
                    preview = s.slice(0, 140) + (s.length > 140 ? "…" : "");
                }
                catch { }
                out.push({ i, ok, tag: tagTried, ch: chHex, preview, mode });
            }
            setRestoreResults(out);
            const okCount = out.filter((r) => r.ok).length;
            setStatus(`✅ Restore complete (${okCount}/${out.length} verified)`);
        }
        catch (e) {
            console.error("restore error", e);
            setStatus("❌ Restore failed: " + (e?.shortMessage || e?.message || String(e)));
        }
    }
    // --- Per-entry downloads ---
    async function onDownloadCipher(r) {
        try {
            const ctHex = await fetchCiphertextByTag(r.tag);
            if (!ctHex)
                return alert("Ciphertext not found in vault for this tag.");
            const fn = `record-${shortAddr(String(recordAddr))}-#${r.i}-${r.ch.slice(2, 10)}.cipher.bin`;
            downloadBytes(hexToBytes(ctHex), fn);
        }
        catch (e) {
            alert("Download failed: " + (e?.shortMessage || e?.message || String(e)));
        }
    }
    async function onDownloadDecrypted(r) {
        try {
            let keyBytes, nonce;
            const chBytes = hexToBytes(r.ch);
            if (r.mode === "legacy") {
                ({ keyBytes, nonce } = await deriveTagKeyNonce_Legacy(account, recordAddr, chBytes));
            }
            else {
                if (!root)
                    return alert("Click “Authorize key derivation (sign)” first.");
                ({ keyBytes, nonce } = await deriveTagKeyNonceFromRoot(root, recordAddr, chBytes));
            }
            const ctHex = await fetchCiphertextByTag(r.tag);
            if (!ctHex)
                return alert("Ciphertext not found in vault for this tag.");
            const pt = await aesGcmDecrypt(keyBytes, nonce, hexToBytes(ctHex));
            // verify against L1 contentHash
            const digest = await sha256Bytes(pt);
            const ok = toHex(digest).toLowerCase() === r.ch.toLowerCase();
            if (!ok)
                return alert("Hash mismatch — refusing to export plaintext.");
            const fn = `record-${shortAddr(String(recordAddr))}-#${r.i}-${r.ch.slice(2, 10)}.fhir.json`;
            downloadBytes(pt, fn, "application/fhir+json");
        }
        catch (e) {
            alert("Download failed: " + (e?.shortMessage || e?.message || String(e)));
        }
    }
    return (_jsxs("div", { style: { padding: 24, fontFamily: "system-ui, sans-serif", maxWidth: 900, margin: "0 auto" }, children: [_jsx("h1", { children: "Prometheus\u2019 Chains \u2014 Patient Web MVP" }), _jsxs("div", { style: { marginBottom: 12 }, children: [_jsx("button", { onClick: connect, children: "Connect Wallet" }), " ", _jsx("button", { onClick: ensureRecord, children: "Check / Create L1 PatientRecord" }), " ", _jsx("button", { onClick: authorizeKeyDerivation, disabled: !recordAddr || recordAddr.endsWith("0000"), children: "Authorize key derivation (sign)" })] }), _jsxs("div", { style: { opacity: 0.85, marginBottom: 16 }, children: [_jsxs("div", { children: [_jsx("b", { children: "Account:" }), " ", account] }), _jsxs("div", { children: [_jsx("b", { children: "Record:" }), " ", recordAddr] }), _jsxs("div", { children: [_jsx("b", { children: "Env:" }), " L1=", env.l1Id, " \u00B7 L2=", env.l2Id] }), root ? _jsx("div", { style: { color: "#0a0" }, children: "\uD83D\uDD11 Key derivation active (session)" }) : null] }), _jsx("h3", { children: "Paste FHIR JSON (plaintext)" }), _jsx("textarea", { rows: 10, style: { width: "100%" }, value: jsonText, onChange: (e) => setJson(e.target.value) }), _jsxs("div", { style: { marginTop: 12 }, children: [_jsx("button", { onClick: hashAndAnchorL1, children: "Generate Hash & Anchor to L1" }), " ", _jsx("button", { onClick: encryptAndStoreL2, children: "Encrypt & Store to L2 Vault" })] }), hashHex && (_jsxs("p", { style: { marginTop: 8, wordBreak: "break-all" }, children: [_jsx("b", { children: "contentHash (L1):" }), " ", hashHex] })), l2Tag && (_jsxs("p", { style: { marginTop: 8, wordBreak: "break-all" }, children: [_jsx("b", { children: "tag (L2):" }), " ", l2Tag] })), lastTx && (_jsxs("p", { style: { marginTop: 8, wordBreak: "break-all" }, children: [_jsx("b", { children: "last tx:" }), " ", lastTx] })), _jsx("hr", { style: { margin: "24px 0" } }), _jsx("h3", { children: "Restore" }), _jsxs("p", { style: { opacity: 0.8, marginTop: -6 }, children: ["We derive tags/keys per-entry from a wallet signature ", _jsx("i", { children: "kept off-chain" }), " and verify against L1 hashes."] }), _jsx("div", { style: { marginTop: 8 }, children: _jsx("button", { onClick: restoreFromWallet, children: "Restore timeline" }) }), restoreResults.length > 0 && (_jsxs("div", { style: { marginTop: 12 }, children: [_jsx("b", { children: "Restored entries:" }), _jsx("ul", { children: restoreResults.map((r) => (_jsxs("li", { style: { margin: "6px 0" }, children: ["#", r.i, " \u2014 tag ", r.tag, " \u2014 ", r.ok ? "✅ verified" : r.missing ? "⚠️ missing on L2" : "❌ hash mismatch", r.mode === "legacy" ? (_jsx("span", { style: { opacity: 0.6 }, children: " (legacy entry)" })) : r.mode === "root" ? (_jsx("span", { style: { opacity: 0.6 }, children: " (wallet-derived)" })) : null, r.preview && (_jsxs("div", { style: { fontSize: 12, opacity: 0.8, wordBreak: "break-all" }, children: ["preview: ", r.preview] })), _jsxs("div", { style: { marginTop: 4 }, children: [_jsx("button", { onClick: () => onDownloadCipher(r), children: "\u2B07 ciphertext" }), " ", _jsx("button", { onClick: () => onDownloadDecrypted(r), disabled: !r.ok, children: "\u2B07 FHIR JSON" })] })] }, r.i))) })] })), _jsx("p", { style: { marginTop: 8 }, children: status }), _jsxs("div", { id: "quick-actions", style: {
                    marginTop: 8,
                    padding: 12,
                    borderRadius: 12,
                    border: "1px solid rgba(0,0,0,0.1)",
                    background: "linear-gradient(180deg, rgba(0,0,0,0.03), rgba(0,0,0,0.01))",
                }, children: [_jsx("b", { children: "Quick actions" }), _jsxs("div", { style: { marginTop: 8 }, children: [_jsx("button", { onClick: encryptAndStoreL2, children: didStore ? "Re-encrypt & Store to L2" : "Encrypt & Store to L2 (Next)" }), " ", _jsx("button", { onClick: hashAndAnchorL1, children: didAnchor ? "Re-anchor on L1" : "Generate Hash & Anchor to L1" })] }), _jsx("div", { style: { fontSize: 12, opacity: 0.75, marginTop: 6 }, children: "Order tip: You can store on L2 first and anchor after, or anchor first and store next \u2014 hashes verify either way." })] }), _jsxs("p", { style: { opacity: 0.7, fontSize: 13, marginTop: 12 }, children: ["Tip: If your deployed vault uses ", _jsx("code", { children: "bytes32" }), " tags, update the ABI types (and derivation slice) accordingly. Also, ensure your vault does ", _jsx("b", { children: "not emit" }), " events with tags/ciphertexts to avoid public tag harvesting."] })] }));
}
