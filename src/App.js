import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState } from "react";
import { createPublicClient, createWalletClient, getContract, custom, http, toHex } from "viem";
import stringify from "json-stable-stringify";
import { hash as sha256Bytes } from "./lib/sdk/crypto/hash"; // <-- use local helper
// --- ENV from Vite (set these in Vercel) ---
const env = {
    l1Id: Number(import.meta.env.VITE_L1_CHAIN_ID), // e.g. 11155111 (Sepolia)
    l1Url: import.meta.env.VITE_L1_RPC_URL,
    l2Id: Number(import.meta.env.VITE_L2_CHAIN_ID), // e.g. 84532 (Base Sepolia)
    factory: import.meta.env.VITE_FACTORY_ADDRESS,
};
// --- Minimal ABIs for Factory & PatientRecord ---
const factoryAbi = [
    { type: "function", name: "recordOf", stateMutability: "view",
        inputs: [{ name: "owner", type: "address" }], outputs: [{ type: "address" }] },
    { type: "function", name: "createRecord", stateMutability: "nonpayable", inputs: [], outputs: [] },
];
const patientRecordAbi = [
    { type: "function", name: "seq", stateMutability: "view", inputs: [], outputs: [{ type: "uint64" }] },
    { type: "function", name: "contentHashAt", stateMutability: "view",
        inputs: [{ type: "uint64" }], outputs: [{ type: "bytes32" }] },
    { type: "function", name: "anchor", stateMutability: "nonpayable",
        inputs: [{ type: "bytes32" }, { type: "uint256" }], outputs: [] },
];
// --- VIEM clients ---
const l1Public = createPublicClient({ chain: { id: env.l1Id }, transport: http(env.l1Url) });
function walletL1() {
    const eth = window.ethereum;
    if (!eth)
        throw new Error("MetaMask not found");
    return createWalletClient({ chain: { id: env.l1Id }, transport: custom(eth) });
}
export default function App() {
    const [account, setAccount] = useState("0x0000000000000000000000000000000000000000");
    const [recordAddr, setRecord] = useState("0x0000000000000000000000000000000000000000");
    const [status, setStatus] = useState("");
    const [jsonText, setJson] = useState('{"resourceType":"Bundle","type":"collection","entry":[{"resource":{"resourceType":"Patient","id":"me"}}]}');
    const [hashHex, setHashHex] = useState("");
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
        setStatus("Checking/creating your L1 PatientRecord…");
        const factory = getContract({ address: env.factory, abi: factoryAbi, client: l1Public });
        let rec = await factory.read.recordOf([account]);
        if (rec === "0x0000000000000000000000000000000000000000") {
            const w = walletL1();
            const [from] = await w.getAddresses();
            const txHash = await w.writeContract({
                address: env.factory,
                abi: factoryAbi,
                functionName: "createRecord",
                account: from,
                chain: undefined
            });
            await l1Public.waitForTransactionReceipt({ hash: txHash });
            rec = await factory.read.recordOf([account]);
        }
        setRecord(rec);
        setStatus(`✅ Record ready: ${rec}`);
    }
    async function computeHash() {
        try {
            const obj = JSON.parse(jsonText);
            const canonical = new TextEncoder().encode(stringify(obj, { space: 0 }));
            const digest = await sha256Bytes(canonical); // Uint8Array(32)
            const hex = toHex(digest); // 0x…
            setHashHex(hex);
            setStatus("✅ Canonical hash computed (ready to anchor)");
        }
        catch (e) {
            setStatus("❌ JSON parse/canonicalize failed: " + (e?.message || String(e)));
        }
    }
    // (Optional) Anchor the hash now — useful to test L1 writes before wiring the vault/L2.
    async function anchorHash() {
        if (!recordAddr || recordAddr === "0x0000000000000000000000000000000000000000") {
            return alert("Ensure your record first");
        }
        if (!hashHex) {
            return alert("Compute the hash first");
        }
        setStatus("Anchoring hash on L1…");
        const w = walletL1();
        const [from] = await w.getAddresses();
        const txHash = await w.writeContract({
            address: recordAddr,
            abi: patientRecordAbi,
            functionName: "anchor",
            args: [hashHex, BigInt(env.l2Id)],
            account: from,
            chain: undefined
        });
        await l1Public.waitForTransactionReceipt({ hash: txHash });
        setStatus("✅ Anchored on L1. (Next: encrypt + store on L2, then anchor.)");
    }
    return (_jsxs("div", { style: { padding: 24, fontFamily: "system-ui, sans-serif", maxWidth: 900, margin: "0 auto" }, children: [_jsx("h1", { children: "Prometheus\u2019 Chains \u2014 Patient Web MVP" }), _jsxs("div", { style: { marginBottom: 12 }, children: [_jsx("button", { onClick: connect, children: "Connect MetaMask" }), " ", _jsx("button", { onClick: ensureRecord, children: "Ensure PatientRecord" }), " "] }), _jsxs("div", { style: { opacity: .8, marginBottom: 16 }, children: [_jsxs("div", { children: [_jsx("b", { children: "Account:" }), " ", account] }), _jsxs("div", { children: [_jsx("b", { children: "Record:" }), " ", recordAddr] }), _jsxs("div", { children: [_jsx("b", { children: "Env:" }), " L1=", env.l1Id, " \u00B7 L2=", env.l2Id] })] }), _jsx("h3", { children: "Paste JSON (e.g., a FHIR Bundle)" }), _jsx("textarea", { rows: 8, style: { width: "100%" }, value: jsonText, onChange: e => setJson(e.target.value) }), _jsxs("div", { style: { marginTop: 12 }, children: [_jsx("button", { onClick: computeHash, children: "Compute Canonical SHA-256" }), " ", _jsx("button", { onClick: anchorHash, disabled: !hashHex || recordAddr === "0x0000000000000000000000000000000000000000", children: "Anchor Hash (L1)" })] }), hashHex && _jsxs("p", { style: { marginTop: 8, wordBreak: "break-all" }, children: [_jsx("b", { children: "contentHash:" }), " ", hashHex] }), _jsx("p", { style: { marginTop: 8 }, children: status })] }));
}
