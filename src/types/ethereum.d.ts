export {};
declare global {
  interface Window {
    ethereum: any; // MetaMask / EIP-1193 provider
  }
}
