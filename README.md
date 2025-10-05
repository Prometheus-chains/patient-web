# patient-web — Prometheus Chains
Web MVP for **patient-owned records**: anchor plaintext hash on L1 (Ethereum), encrypt & store on L2 (Base), and **Restore** via wallet-derived keys.

![License](https://img.shields.io/badge/license-Apache--2.0-blue)

## ✨ What it does
- **Anchor-first workflow**: Canonicalize FHIR JSON → SHA-256 → `contentHash` → append to your `PatientRecord` on L1.  
- **Encrypt & store**: Derive {tag, key, nonce} from a one-time EIP-712 signature; encrypt with **AES-GCM**; store ciphertext in the L2 **Vault** by secret tag.  
- **Restore**: Re-derive {tag, key, nonce}, fetch ciphertext by tag, decrypt locally, and verify `SHA-256(pt) == contentHash` from L1.  
  (Integrity & ordering on L1; storage & privacy on L2.)  
  _Implementation details match the app code and workflow spec._  

## 🧭 How it works (at a glance)
1) **Ensure record** (deploy/lookup your `PatientRecord`).  
2) **Authorize key derivation** (EIP-712 sign → in-memory session root).  
3) **Anchor on L1** (hash canonical FHIR JSON → `anchor(contentHash, l2ChainId)`).  
4) **Encrypt & store on L2** (deterministic tag/key/nonce → `Vault.put(ciphertext, tag)`).  
5) **Restore** (loop i=1..seq: derive → fetch → decrypt → verify).

## 🧑‍💻 Quickstart
```bash
pnpm i
pnpm dev


# React + TypeScript + Vite

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Babel](https://babeljs.io/) for Fast Refresh
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/) for Fast Refresh

## Expanding the ESLint configuration

If you are developing a production application, we recommend updating the configuration to enable type-aware lint rules:

```js
export default tseslint.config([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      // Other configs...

      // Remove tseslint.configs.recommended and replace with this
      ...tseslint.configs.recommendedTypeChecked,
      // Alternatively, use this for stricter rules
      ...tseslint.configs.strictTypeChecked,
      // Optionally, add this for stylistic rules
      ...tseslint.configs.stylisticTypeChecked,

      // Other configs...
    ],
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.node.json', './tsconfig.app.json'],
        tsconfigRootDir: import.meta.dirname,
      },
      // other options...
    },
  },
])
```

You can also install [eslint-plugin-react-x](https://github.com/Rel1cx/eslint-react/tree/main/packages/plugins/eslint-plugin-react-x) and [eslint-plugin-react-dom](https://github.com/Rel1cx/eslint-react/tree/main/packages/plugins/eslint-plugin-react-dom) for React-specific lint rules:

```js
// eslint.config.js
import reactX from 'eslint-plugin-react-x'
import reactDom from 'eslint-plugin-react-dom'

export default tseslint.config([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      // Other configs...
      // Enable lint rules for React
      reactX.configs['recommended-typescript'],
      // Enable lint rules for React DOM
      reactDom.configs.recommended,
    ],
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.node.json', './tsconfig.app.json'],
        tsconfigRootDir: import.meta.dirname,
      },
      // other options...
    },
  },
])
```
