import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState } from "react";
import { createPublicClient, createWalletClient, getContract, custom, http, toHex, hexToBytes, } from "viem";
import stringify from "json-stable-stringify";
import { hash as sha256Bytes } from "./lib/sdk/crypto/hash"; // Uint8Array sha256
// ────────────────────────────────────────────────────────────────────────────────
// ENV (Vite)
// ────────────────────────────────────────────────────────────────────────────────
const env = {
    l1Id: Number(import.meta.env.VITE_L1_CHAIN_ID), // e.g. 11155111 (Sepolia)
    l1Url: import.meta.env.VITE_L1_RPC_URL,
    l2Id: Number(import.meta.env.VITE_L2_CHAIN_ID), // e.g. 84532 (Base Sepolia)
    l2Url: import.meta.env.VITE_L2_RPC_URL,
    factory: import.meta.env.VITE_FACTORY_ADDRESS,
    vault: import.meta.env.VITE_VAULT_ADDRESS,
};
// Help MetaMask add/switch chains if needed
const PRESETS = {
    11155111: { chainName: "Sepolia", explorer: "https://sepolia.etherscan.io", symbol: "ETH" },
    84532: { chainName: "Base Sepolia", explorer: "https://sepolia.basescan.org", symbol: "ETH" },
};
// ────────────────────────────────────────────────────────────────────────────────
// Minimal ABIs (match on-chain contracts exactly)
// ────────────────────────────────────────────────────────────────────────────────
const factoryAbi = [
    { type: "function", name: "recordOf", stateMutability: "view", inputs: [{ name: "owner", type: "address" }], outputs: [{ type: "address" }] },
    { type: "function", name: "createRecord", stateMutability: "nonpayable", inputs: [], outputs: [{ type: "address" }] },
];
const patientRecordAbi = [
    { type: "function", name: "seq", stateMutability: "view", inputs: [], outputs: [{ type: "uint64" }] },
    { type: "function", name: "contentHashAt", stateMutability: "view", inputs: [{ type: "uint64" }], outputs: [{ type: "bytes32" }] },
    { type: "function", name: "anchor", stateMutability: "nonpayable", inputs: [{ type: "bytes32" }, { type: "uint32" }], outputs: [{ type: "uint64" }] },
];
// Vault (L2): write + reads
const vaultWriteAbi = [
    // function put(bytes ciphertext, bytes16 tag) external returns (bytes32 envelopeId)
    { type: "function", name: "put", stateMutability: "nonpayable", inputs: [{ name: "ciphertext", type: "bytes" }, { name: "tag", type: "bytes16" }], outputs: [{ type: "bytes32" }] },
];
const vaultReadAbi = [
    { type: "function", name: "getCiphertextByTag", stateMutability: "view", inputs: [{ type: "bytes16" }], outputs: [{ type: "bytes" }] },
    { type: "function", name: "getEnvelopeIdByTag", stateMutability: "view", inputs: [{ type: "bytes16" }], outputs: [{ type: "bytes32" }] },
    { type: "function", name: "getCiphertext", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ type: "bytes" }] },
];
// ────────────────────────────────────────────────────────────────────────────────
// viem clients & wallet helpers
// ────────────────────────────────────────────────────────────────────────────────
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
        if (e?.code === 4902) {
            const p = PRESETS[targetId] || { chainName: `Chain ${targetId}`, explorer: "", symbol: "ETH" };
            await eth.request({ method: "wallet_addEthereumChain", params: [{ chainId: chainIdHex, chainName: p.chainName, rpcUrls: rpcUrl ? [rpcUrl] : [""], nativeCurrency: { name: p.symbol, symbol: p.symbol, decimals: 18 }, blockExplorerUrls: p.explorer ? [p.explorer] : [] }] });
            await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId: chainIdHex }] });
        }
        else {
            throw e;
        }
    }
}
// ────────────────────────────────────────────────────────────────────────────────
// Crypto helpers & deterministic derivation (CURRENT METHOD ONLY)
// ────────────────────────────────────────────────────────────────────────────────
const enc = new TextEncoder();
const dec = new TextDecoder();
function concatBytes(...arrs) {
    const total = arrs.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrs) {
        out.set(a, off);
        off += a.length;
    }
    return out;
}
function u64be(n) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), false); return b; }
// Off-chain wallet-bound root via EIP-712 (session-only secret)
async function deriveRootViaSignature(recordAddr) {
    await ensureChain(env.l1Id, env.l1Url); // ensure chainId in domain matches wallet
    const w = walletL1();
    const [from] = await w.getAddresses();
    const sig = await w.signTypedData({
        account: from,
        domain: { name: "PrometheusChains", version: "1", chainId: env.l1Id, verifyingContract: recordAddr },
        types: { Derive: [{ name: "purpose", type: "string" }, { name: "record", type: "address" }, { name: "l2", type: "uint256" }] },
        primaryType: "Derive",
        message: { purpose: "pc-key-derivation-v1", record: recordAddr, l2: BigInt(env.l2Id) },
    });
    return await sha256Bytes(hexToBytes(sig)); // 32-byte root
}
// CURRENT derivation: (root, recordAddr, index) → tag(16), key(32), nonce(12)
async function deriveTagKeyNonceFromRootIndex(root, recordAddr, i) {
    const base = concatBytes(enc.encode("PC-DERIVE-ROOT-I"), root, hexToBytes(recordAddr), u64be(i));
    const tag = (await sha256Bytes(concatBytes(enc.encode("TAG"), base))).slice(0, 16); // bytes16
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
function canonicalBytesFromJson(text) {
    const obj = JSON.parse(text);
    return enc.encode(stringify(obj, { space: 0 }));
}
// L2 vault read (fixed to current contract reads)
async function fetchCiphertextByTag(tagHex) {
    const vault = getContract({ address: env.vault, abi: vaultReadAbi, client: l2Public });
    try {
        const byTag = (await vault.read.getCiphertextByTag([tagHex]));
        if (byTag && byTag !== "0x")
            return byTag;
    }
    catch { }
    try {
        const envId = (await vault.read.getEnvelopeIdByTag([tagHex]));
        if (envId && envId !== "0x".padEnd(66, "0")) {
            const byId = (await vault.read.getCiphertext([envId]));
            if (byId && byId !== "0x")
                return byId;
        }
    }
    catch { }
    return null;
}
export default function App() {
    const [account, setAccount] = useState("0x0000000000000000000000000000000000000000");
    const [recordAddr, setRecord] = useState("0x0000000000000000000000000000000000000000");
    const [status, setStatus] = useState("");
    const [jsonText, setJson] = useState('{"resourceType":"Bundle","type":"collection","entry":[{"resource":{"resourceType":"Patient","id":"me"}}]}');
    const [hashHex, setHashHex] = useState("");
    const [l2Tag, setL2Tag] = useState("");
    const [lastTx, setLastTx] = useState("");
    // Session root (from wallet signature)
    const [root, setRoot] = useState(null);
    // Restore
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
        if (!account || account === "0x0000000000000000000000000000000000000000")
            return alert("Connect MetaMask first");
        await ensureChain(env.l1Id, env.l1Url);
        setStatus("Checking/creating your L1 PatientRecord…");
        const factory = getContract({ address: env.factory, abi: factoryAbi, client: l1Public });
        let rec = (await factory.read.recordOf([account]));
        if (rec === "0x0000000000000000000000000000000000000000") {
            const w = walletL1();
            const [from] = await w.getAddresses();
            const { request } = await l1Public.simulateContract({ address: env.factory, abi: factoryAbi, functionName: "createRecord", account: from });
            const txHash = await w.writeContract(request);
            setStatus("Tx sent to create record — waiting for confirmation…");
            setLastTx(txHash);
            await l1Public.waitForTransactionReceipt({ hash: txHash, confirmations: 1 });
            rec = (await factory.read.recordOf([account]));
        }
        setRecord(rec);
        setStatus(`✅ Record ready: ${rec}`);
    }
    async function authorizeKeyDerivation() {
        try {
            if (!recordAddr || recordAddr.endsWith("0000"))
                return alert("Ensure your record first");
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
            if (!recordAddr || recordAddr.endsWith("0000"))
                return alert("Ensure your record first");
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
            const { request } = await l1Public.simulateContract({ address: recordAddr, abi: patientRecordAbi, functionName: "anchor", args: [hex, env.l2Id], account: from });
            setStatus("Requesting wallet confirmation…");
            const txHash = await w.writeContract(request);
            setLastTx(txHash);
            setStatus("Tx sent — waiting for 1 confirmation…");
            await l1Public.waitForTransactionReceipt({ hash: txHash, confirmations: 1 });
            setStatus("✅ Anchored on L1. Now encrypt & store on L2 for this entry.");
            document.getElementById("quick-actions")?.scrollIntoView({ behavior: "smooth", block: "center" });
        }
        catch (e) {
            console.error("anchor error", e);
            setStatus("❌ L1 anchor failed: " + (e?.shortMessage || e?.message || String(e)));
        }
    }
    // SIMPLIFIED: anchor-first only. We always store for index = current seq (just appended).
    async function encryptAndStoreL2() {
        try {
            if (!account || account.endsWith("0000"))
                return alert("Connect MetaMask first");
            if (!recordAddr || recordAddr.endsWith("0000"))
                return alert("Ensure your record first");
            if (!root)
                return alert("Click “Authorize key derivation (sign)” first.");
            // Determine current seq on L1; require at least 1 anchor.
            const rec = getContract({ address: recordAddr, abi: patientRecordAbi, client: l1Public });
            const seq = Number(await rec.read.seq());
            if (seq === 0)
                return alert("Anchor to L1 first, then store to L2.");
            const i = seq; // store for the just-anchored entry
            setStatus(`Switching to L2…`);
            await ensureChain(env.l2Id, env.l2Url);
            setStatus(`Encrypting snapshot #${i} and storing on L2…`);
            const canonical = canonicalBytesFromJson(jsonText);
            const { tagHex, keyBytes, nonce } = await deriveTagKeyNonceFromRootIndex(root, recordAddr, i);
            const ciphertext = await aesGcmEncrypt(keyBytes, nonce, canonical);
            const ctHex = toHex(ciphertext);
            const w = walletL2();
            const [from] = await w.getAddresses();
            // put(bytes ciphertext, bytes16 tag) → returns bytes32 envelopeId
            const { request } = await l2Public.simulateContract({ address: env.vault, abi: vaultWriteAbi, functionName: "put", args: [ctHex, tagHex], account: from });
            const txHash = await w.writeContract(request);
            setLastTx(txHash);
            setStatus("Tx sent — waiting for L2 confirmation…");
            await l2Public.waitForTransactionReceipt({ hash: txHash, confirmations: 1 });
            setL2Tag(tagHex);
            setStatus(`✅ Stored snapshot #${i} on L2.`);
            document.getElementById("quick-actions")?.scrollIntoView({ behavior: "smooth", block: "center" });
        }
        catch (e) {
            console.error("l2 store error", e);
            setStatus("❌ L2 store failed: " + (e?.shortMessage || e?.message || String(e)));
        }
    }
    async function restoreFromWallet() {
        try {
            if (!recordAddr || recordAddr.endsWith("0000"))
                return alert("Ensure your record first");
            if (!root)
                return alert("Click “Authorize key derivation (sign)” first.");
            setStatus("Restoring with wallet-bound derivation…");
            const rec = getContract({ address: recordAddr, abi: patientRecordAbi, client: l1Public });
            const seq = Number(await rec.read.seq());
            const out = [];
            for (let i = 1; i <= seq; i++) {
                const chHex = (await rec.read.contentHashAt([BigInt(i)])); // hash of PLAINTEXT
                const { tagHex, keyBytes, nonce } = await deriveTagKeyNonceFromRootIndex(root, recordAddr, i);
                const ctHex = await fetchCiphertextByTag(tagHex);
                if (!ctHex || ctHex === "0x") {
                    out.push({ i, ok: false, tag: tagHex, ch: chHex, missing: true });
                    continue;
                }
                const pt = await aesGcmDecrypt(keyBytes, nonce, hexToBytes(ctHex));
                const check = await sha256Bytes(pt);
                const ok = toHex(check).toLowerCase() === chHex.toLowerCase();
                let preview;
                try {
                    const j = JSON.parse(dec.decode(pt));
                    const s = JSON.stringify(j);
                    preview = s.slice(0, 140) + (s.length > 140 ? "…" : "");
                }
                catch { }
                out.push({ i, ok, tag: tagHex, ch: chHex, preview });
            }
            setRestoreResults(out);
            const okCount = out.filter(r => r.ok).length;
            setStatus(`✅ Restore complete (${okCount}/${out.length} verified)`);
        }
        catch (e) {
            console.error("restore error", e);
            setStatus("❌ Restore failed: " + (e?.shortMessage || e?.message || String(e)));
        }
    }
    function shortAddr(a) { return `${a.slice(0, 6)}…${a.slice(-4)}`; }
    function downloadBytes(bytes, filename, mime = "application/octet-stream") {
        const blob = new Blob([bytes], { type: mime });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    }
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
            if (!root)
                return alert("Click “Authorize key derivation (sign)” first.");
            const { keyBytes, nonce } = await deriveTagKeyNonceFromRootIndex(root, recordAddr, r.i);
            const ctHex = await fetchCiphertextByTag(r.tag);
            if (!ctHex)
                return alert("Ciphertext not found in vault for this tag.");
            const pt = await aesGcmDecrypt(keyBytes, nonce, hexToBytes(ctHex));
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
    return (_jsxs("div", { style: { padding: 24, fontFamily: "system-ui, sans-serif", maxWidth: 900, margin: "0 auto" }, children: [_jsx("h1", { children: "Prometheus\u2019 Chains \u2014 Patient Web MVP" }), _jsxs("div", { style: { marginBottom: 12 }, children: [_jsx("button", { onClick: connect, children: "Connect Wallet" }), " ", _jsx("button", { onClick: ensureRecord, children: "Check / Create L1 PatientRecord" }), " ", _jsx("button", { onClick: authorizeKeyDerivation, disabled: !recordAddr || recordAddr.endsWith("0000"), children: "Authorize key derivation (sign)" })] }), _jsxs("div", { style: { opacity: 0.85, marginBottom: 16 }, children: [_jsxs("div", { children: [_jsx("b", { children: "Account:" }), " ", account] }), _jsxs("div", { children: [_jsx("b", { children: "Record:" }), " ", recordAddr] }), _jsxs("div", { children: [_jsx("b", { children: "Env:" }), " L1=", env.l1Id, " \u00B7 L2=", env.l2Id] }), root ? _jsx("div", { style: { color: "#0a0" }, children: "\uD83D\uDD11 Key derivation active (session)" }) : null] }), _jsx("h3", { children: "Paste FHIR JSON (plaintext)" }), _jsx("textarea", { rows: 10, style: { width: "100%" }, value: jsonText, onChange: (e) => setJson(e.target.value) }), _jsxs("div", { style: { marginTop: 12 }, children: [_jsx("button", { onClick: hashAndAnchorL1, children: "Generate Hash & Anchor to L1" }), " ", _jsx("button", { onClick: encryptAndStoreL2, children: "Encrypt & Store to L2 Vault" })] }), hashHex && _jsxs("p", { style: { marginTop: 8, wordBreak: "break-all" }, children: [_jsx("b", { children: "contentHash (L1):" }), " ", hashHex] }), l2Tag && _jsxs("p", { style: { marginTop: 8, wordBreak: "break-all" }, children: [_jsx("b", { children: "tag (L2):" }), " ", l2Tag] }), lastTx && _jsxs("p", { style: { marginTop: 8, wordBreak: "break-all" }, children: [_jsx("b", { children: "last tx:" }), " ", lastTx] }), _jsx("hr", { style: { margin: "24px 0" } }), _jsx("h3", { children: "Restore" }), _jsxs("p", { style: { opacity: 0.8, marginTop: -6 }, children: ["We derive tag/key/nonce from your wallet signature (off-chain) + record + ", _jsx("b", { children: "index" }), ", fetch ciphertext by tag from L2, decrypt locally, then verify hash against L1."] }), _jsx("div", { style: { marginTop: 8 }, children: _jsx("button", { onClick: restoreFromWallet, children: "Restore timeline" }) }), restoreResults.length > 0 && (_jsxs("div", { style: { marginTop: 12 }, children: [_jsx("b", { children: "Restored entries:" }), _jsx("ul", { children: restoreResults.map((r) => (_jsxs("li", { style: { margin: "6px 0" }, children: ["#", r.i, " \u2014 tag ", r.tag, " \u2014 ", r.ok ? "✅ verified" : r.missing ? "⚠️ missing on L2" : "❌ hash mismatch", r.preview && (_jsxs("div", { style: { fontSize: 12, opacity: 0.8, wordBreak: "break-all" }, children: ["preview: ", r.preview] })), _jsxs("div", { style: { marginTop: 4 }, children: [_jsx("button", { onClick: () => onDownloadCipher(r), children: "\u2B07 ciphertext" }), " ", _jsx("button", { onClick: () => onDownloadDecrypted(r), disabled: !r.ok, children: "\u2B07 FHIR JSON" })] })] }, r.i))) })] })), _jsx("p", { style: { marginTop: 8 }, children: status }), _jsxs("div", { id: "quick-actions", style: { marginTop: 8, padding: 12, borderRadius: 12, border: "1px solid rgba(0,0,0,0.1)", background: "linear-gradient(180deg, rgba(0,0,0,0.03), rgba(0,0,0,0.01))" }, children: [_jsx("b", { children: "Quick actions" }), _jsxs("div", { style: { marginTop: 8 }, children: [_jsx("button", { onClick: hashAndAnchorL1, children: "Generate Hash & Anchor to L1" }), " ", _jsx("button", { onClick: encryptAndStoreL2, children: "Encrypt & Store to L2" })] }), _jsxs("div", { style: { fontSize: 12, opacity: 0.75, marginTop: 6 }, children: ["Order: ", _jsx("b", { children: "Anchor on L1 first" }), " for the snapshot you just pasted, then ", _jsx("b", { children: "Store on L2" }), " for that same index."] })] })] }));
}
