# Web dependencies

Exact versions are pinned in `web/package.json` and locked in `web/pnpm-lock.yaml`. This file covers the web section only; the Python section is maintained in `core/DEPENDENCIES.md` on the backend branch and will be merged here. No AI or machine-learning package is a dependency.

## Runtime dependencies

| Package | Version | Why |
|---|---|---|
| `@fontsource/ibm-plex-mono` | 5.3.0 | Self-hosted IBM Plex Mono (400, 500) for machine-produced text; imported in `src/index.css`. |
| `@fontsource/ibm-plex-sans` | 5.3.0 | Self-hosted IBM Plex Sans (400, 500, 600) for interface text; imported in `src/index.css`. |
| `@fontsource/instrument-serif` | 5.3.0 | Self-hosted Instrument Serif (400, 400 italic) for display lines; imported in `src/index.css`. |
| `@noble/ciphers` | 2.4.0 | AES-GCM (`src/crypto/noble.ts`) and constant-time byte comparison (`src/crypto/bytes.ts`). |
| `@noble/curves` | 2.4.0 | Ed25519 in the browser crypto provider (`src/crypto/noble.ts`). |
| `@noble/hashes` | 2.4.0 | Argon2id, HKDF, HMAC, SHA-256 and SHA-384, and random bytes (`src/crypto/noble.ts`, `src/client/real/worker.ts`). |
| `@noble/post-quantum` | 0.7.1 | ML-KEM-768 with X25519 hybrid KEM (`ml_kem768_x25519`) and ML-DSA-65 (`src/crypto/noble.ts`). |
| `@tanstack/react-query` | 5.107.1 | Server-state fetching and caching; `QueryClient` set up in `src/main.tsx`, used across screens. |
| `class-variance-authority` | 0.7.1 | Variant classes for shadcn components (`button.tsx`, `tabs.tsx`, `field.tsx`, `alert.tsx` and others). |
| `cmdk` | 1.1.1 | Command palette primitive behind `src/components/ui/command.tsx`. |
| `cn` | 0.5.2 | The `cn` class-name merge helper, re-exported from `src/lib/utils.ts` and used by every shadcn component. |
| `driver.js` | 1.12.1 | Guided tour engine in `src/tour/Tour.tsx`; its stylesheet is imported and restyled in `src/tour/tour.css`. |
| `idb-keyval` | 6.3.0 | IndexedDB store for the passphrase-protected device keystore (`src/crypto/keystore.ts`). |
| `lucide-react` | 1.72.0 | Icons (only icon set used) across the shell, landing and shadcn components. |
| `motion` | 14.12.0 | Animation library; `motion/react` is used in `src/motion/WrapBeams.tsx`, `RevokeCut.tsx` and `KeyIssue.tsx`. |
| `radix-ui` | 1.8.1 | Accessible primitives behind the shadcn components in `src/components/ui/` (imported as the `radix-ui` umbrella package). |
| `react` | 19.3.1 | UI library. |
| `react-dom` | 19.3.1 | React renderer for the browser (`src/main.tsx`). |
| `react-router` | 8.5.1 | Routing for the public site and the console (`src/main.tsx`, `src/app/routes.tsx`). |
| `recharts` | 3.8.0 | Bar chart on the overview screen (`src/app/screens/Overview.tsx`) and the shadcn `chart.tsx` wrapper. |
| `shadcn` | 4.23.0 | Provides `shadcn/tailwind.css`, imported in `src/index.css`; also the CLI that generated the vendored components. |
| `tw-animate-css` | 1.4.0 | Animation utilities used by shadcn component classes; imported in `src/index.css`. |

## Development dependencies

| Package | Version | Why |
|---|---|---|
| `@playwright/test` | 1.65.0 | End-to-end test runner (`e2e/*.spec.ts`, `playwright.config.ts`). |
| `@tailwindcss/vite` | 4.3.5 | Tailwind CSS v4 Vite plugin (`vite.config.ts`). |
| `@types/node` | 24.19.2 | Node typings for `vite.config.ts` and other config files (`tsconfig.node.json` lists `node` types). |
| `@types/react` | 19.3.0 | React type definitions. |
| `@types/react-dom` | 19.3.0 | React DOM type definitions. |
| `@vitejs/plugin-react` | 6.3.0 | React plugin for Vite (`vite.config.ts`). |
| `oxlint` | 1.93.0 | Linter, run by the `lint` script (config in `.oxlintrc.json`). |
| `tailwindcss` | 4.3.5 | Utility CSS framework (`@import "tailwindcss"` in `src/index.css`). |
| `typescript` | 7.0.2 | Type checking via `tsc -b` in the `build` and `typecheck` scripts. |
| `vite` | 8.3.8 | Dev server and bundler (`vite.config.ts`). |
| `vitest` | 5.1.0 | Unit test runner (`test` and `test:crypto` scripts; `vitest.config.ts`). |

## Installed but unused

None. Every dependency in `web/package.json` is imported by the source, the tests or the build configuration (the `@axe-core/playwright` scans live in `web/e2e`).
