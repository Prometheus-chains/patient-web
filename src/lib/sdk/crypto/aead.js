/* SPDX-License-Identifier: Apache-2.0 */
export async function encrypt(pt, key, nonce) {
    const k = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, k, pt);
    return new Uint8Array(ct);
}
export async function decrypt(ct, key, nonce) {
    const k = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, k, ct);
    return new Uint8Array(pt);
}
