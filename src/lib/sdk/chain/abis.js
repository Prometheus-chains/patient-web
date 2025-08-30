/* SPDX-License-Identifier: Apache-2.0 */
export const patientRecordAbi = [
    { "type": "function", "name": "seq", "stateMutability": "view", "inputs": [], "outputs": [{ "type": "uint64" }] },
    { "type": "function", "name": "contentHashAt", "stateMutability": "view", "inputs": [{ "type": "uint64" }], "outputs": [{ "type": "bytes32" }] },
    { "type": "function", "name": "anchor", "stateMutability": "nonpayable", "inputs": [{ "type": "bytes32" }, { "type": "uint256" }], "outputs": [] }
];
export const factoryAbi = [
    { "type": "function", "name": "recordOf", "stateMutability": "view", "inputs": [{ "type": "address" }], "outputs": [{ "type": "address" }] },
    { "type": "function", "name": "createRecord", "stateMutability": "nonpayable", "inputs": [], "outputs": [] }
];
export const vaultAbi = [
    { "type": "function", "name": "put", "stateMutability": "nonpayable", "inputs": [{ "name": "tag", "type": "bytes32" }, { "name": "ciphertext", "type": "bytes" }], "outputs": [] }
];
// If your Vault ABI differs (extra args/events), update vaultAbi accordingly.
