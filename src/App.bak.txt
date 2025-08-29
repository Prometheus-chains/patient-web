import { useState } from "react";

export default function App() {
  const [account, setAccount] = useState<string>("");

  async function connect() {
    const eth = (window as any).ethereum;
    if (!eth) { alert("MetaMask not found"); return; }
    const [addr] = await eth.request({ method: "eth_requestAccounts" });
    setAccount(addr);
  }

  return (
    <div style={{ padding: 24, fontFamily: "system-ui, sans-serif" }}>
      <h1>Prometheus’ Chains — Patient Web MVP</h1>
      <button onClick={connect}>Connect MetaMask</button>
      {account && <p>Connected: {account}</p>}
      <p style={{opacity:.7, marginTop:16}}>
        Env: L1={import.meta.env.VITE_L1_CHAIN_ID} · L2={import.meta.env.VITE_L2_CHAIN_ID}
      </p>
    </div>
  );
}