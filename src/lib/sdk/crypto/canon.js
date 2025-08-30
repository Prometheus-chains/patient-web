/* SPDX-License-Identifier: Apache-2.0 */
import stringify from "json-stable-stringify";
export function canonicalize(obj) {
    const s = stringify(obj, { space: 0 }); // stable keys, no spaces
    return new TextEncoder().encode(s);
}
