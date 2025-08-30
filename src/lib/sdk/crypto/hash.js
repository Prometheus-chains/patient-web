/* SPDX-License-Identifier: Apache-2.0 */
// SHA-256 using Web Crypto. Returns raw 32-byte digest.
export async function hash(bytes) {
    const buf = await crypto.subtle.digest("SHA-256", bytes);
    return new Uint8Array(buf);
}
