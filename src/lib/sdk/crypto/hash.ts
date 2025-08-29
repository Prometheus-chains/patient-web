/* SPDX-License-Identifier: Apache-2.0 */
import { sha256 } from "@noble/hashes";
export const hash = (bytes: Uint8Array) => sha256(bytes);