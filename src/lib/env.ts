export const env = {
  l1Id: Number(import.meta.env.VITE_L1_CHAIN_ID),
  l2Id: Number(import.meta.env.VITE_L2_CHAIN_ID),
  l1Url: import.meta.env.VITE_L1_RPC_URL as string,
  l2Url: import.meta.env.VITE_L2_RPC_URL as string,
  factory: import.meta.env.VITE_FACTORY_ADDRESS as `0x${string}`,
  vault: import.meta.env.VITE_VAULT_ADDRESS as `0x${string}`,
};