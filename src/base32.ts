export function base32_encode(data: ArrayBuffer) {
    const enc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const v = new DataView(data);
    // groups of 5 bytes, 40 bits, and 8 base32 chars
    const remainder = v.byteLength % 8 || 8; // 8 bytes for uint64
    const result = [];
    let window; // 5 byte window backed by a 64 bit primitive
    for (let offset = 0; offset < v.byteLength - remainder; offset += 5) {
        window = v.getBigUint64(offset) >> 24n;
        for (let i = 35n; i >= 0; i -= 5n) result.push(enc[Number((window >> i) & 0b11111n)]);
    }
    window = 0n;
    for (let r = remainder; r > 0; --r) window = (window << 8n) | BigInt(v.getUint8(v.byteLength-r));
    const bitPad = 5 - ((remainder * 8) % 5 || 5);
    window <<= BigInt(bitPad);
    for (let i = BigInt(remainder * 8 - 5 + bitPad); i >= 0; i -= 5n) result.push(enc[Number((window >> i) & 0b11111n)]);

    return result.join('') + '='.repeat(8 - (result.length % 8 || 8));
}