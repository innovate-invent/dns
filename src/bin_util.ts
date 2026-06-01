export type TokenType =
    's16'
    | 'u8'
    | 'u16'
    | 'string'
    | 'u32'
    | 'u48'
    | 'string[]'
    | 'string[*]'
    | string
    | 'u3'
    | 'u4'
    | 'bit'
    | 'opaque'
    | number;
export type TokenVal = number | BigInt | string | string[] | ArrayBuffer | undefined | DataView;
export type Tokenizer = Generator<TokenVal, undefined, TokenType>;

/**
 * Deserialize binary given a series of tokens
 * Returns a Generator that accepts 's16'|'u8'|'u16'|'string'|'u32'|'string[]'|'string[*]'|'u3'|'u4'|'bit'|'u15'|'opaque'|number as a parameter
 * The generator will consume bytes and yield the related native type.
 * Pass undefined to yield the current byte offset, or a number to advance the byte offset by the value number of bytes.
 * @param data buffer populated with data to deserialize
 * @param start buffer start offset
 * @param end buffer end offset
 */
export function* deserialize(data: ArrayBuffer, start: number = 0, end?: number): Tokenizer {
    const view = new DataView(data, start, end && end - start);
    let ptrView;
    let len = 0;
    let val;
    let strlen;
    for (let bitOffset = 0; bitOffset < view.byteLength * 8; bitOffset += len) {
        len = 0;
        const byteOffset = Math.trunc(bitOffset / 8);
        const type = yield val;
        switch (type) { // TODO replace with Symbols
            case 's16':
                val = view.getInt16(byteOffset);
                // Currently all s16 values are byte aligned, no shifting required
                len = 16;
                break;
            case 'u8':
                val = view.getUint8(byteOffset);
                // Currently all u8 values are byte aligned, no shifting required
                len = 8;
                break;
            case 'u16':
                val = view.getUint16(byteOffset);
                // Currently all u16 values are byte aligned, no shifting required
                len = 16;
                break;
            case 'u32':
                val = view.getUint32(byteOffset);
                // Currently all u32 values are byte aligned, no shifting required
                len = 32;
                break;
            case 'u48':
                val = (BigInt(view.getUint16(byteOffset)) << 32n) | BigInt(view.getUint32(byteOffset+2));
                // Currently all u48 values are byte aligned, no shifting required
                len = 48;
                break;
            case 'u3':
                // Only used by header Z field
                val = undefined;
                len = 3;
                break;
            case 'u15':
                // Only used by OPT Z field
                val = undefined;
                len = 15;
                break;
            case 'u2':
                val = view.getUint16(byteOffset);
                val = 0b11 & (val >> (13 - (bitOffset % 8)));
                len = 2;
                break;
            case 'u4':
                val = view.getUint16(byteOffset);
                val = 0b1111 & (val >> (11 - (bitOffset % 8)));
                len = 4;
                break;
            case 'bit':
                val = view.getUint8(byteOffset);
                val = 0b1 & (val >> (7 - (bitOffset % 8)));
                len = 1;
                break;
            case 'opaque': // Consume remainder of data
                yield data.slice(byteOffset + start, end);
                return;
            case 'bytes':
                strlen = view.getUint8(byteOffset);
                val = data.slice(byteOffset + start + 1, byteOffset + start + strlen + 1);
                len += (strlen + 1) * 8;
                break;
            case 'string[*]': // Consume remainder of data as string
                yield String.fromCodePoint(...new Uint8Array(data.slice(byteOffset + start, end)));
                return;
            case 'string': // Length prefixed string
                strlen = view.getUint8(byteOffset);
                val = String.fromCodePoint(...new Uint8Array(data.slice(byteOffset + start + 1, byteOffset + start + strlen + 1)));
                len += (strlen + 1) * 8;
                break;
            case 'string[]': // Array of length prefixed strings, zero terminated or until end of data
                val = [];
                let ptr;
                while (ptr === undefined && byteOffset + len < view.byteLength) {
                    strlen = view.getUint8(byteOffset + len);
                    if (strlen > 63) {
                        strlen = view.getUint16(byteOffset + len);
                        ptr = strlen & 0b0011111111111111;
                        len += 2;
                        break;
                    } else len += 1;
                    if (strlen === 0) {
                        val.push("");
                        break;
                    } else {
                        val.push(String.fromCodePoint(...new Uint8Array(data.slice(byteOffset + start + len, byteOffset + start + len + strlen))));
                        len += strlen;
                    }
                }
                if (ptr !== undefined) {
                    if (!ptrView) ptrView = new DataView(data);
                    // https://tools.ietf.org/html/rfc1035#section-4.1.4
                    while (true) {
                        strlen = ptrView.getUint8(ptr);
                        ++ptr;
                        if (strlen === 0) {
                            val.push("");
                            break;
                        } else if (strlen > 63) {
                            strlen = view.getUint16(ptr);
                            ptr = strlen & 0b0011111111111111;
                        } else {
                            val.push(String.fromCodePoint(...new Uint8Array(data.slice(ptr, ptr + strlen))));
                            ptr += strlen;
                        }
                    }
                }
                len *= 8;
                break;
            case undefined:  // Return current byteOffset if no type provided
                val = byteOffset;
                break;
            case 'view':
                val = view;
                break;
            default:
                if (typeof type === 'number') {
                    len = type * 8;
                } else if (typeof type === 'string' && (type as string).startsWith('string[')) {
                    len = parseInt((type as string).substring(7, (type as string).length - 1), 10);
                    val = String.fromCodePoint(...new Uint8Array(data.slice(byteOffset + start, byteOffset + start + len)));
                    len *= 8;
                } else throw Error('Unknown token type');
        }
    }
    yield val;
    return;
}

// TODO implement https://tools.ietf.org/html/rfc1035#section-2.3.4
// TODO support truncated responses

function setString(view: DataView, val: string) {
    let len = 0;
    view.setUint8(0, val.length);
    for (; len < val.length; ++len) {
        view.setUint8(1 + len, val.charCodeAt(len));
    }
}

/**
 * Serialize binary given data and a series of tokens
 * Returns a Generator that accepts tuples of ('s16'|'u8'|'u16'|'string'|'u32'|'string[]'|'string[*]'|'u3'|'u4'|'bit'|'u15'|'opaque', number|string|string[]|ArrayBuffer) as a parameter
 * The generator will convert the second tuple value to the binary representation specified in the first tuple value
 * @param data buffer to populate
 */
export function* serialize(data: ArrayBuffer): Generator<number, undefined, [TokenType, TokenVal]> {
    const view = new DataView(data);
    let len = 0;
    let bigval;

    for (let bitOffset = 0; bitOffset < view.byteLength * 8; bitOffset += len) {
        len = 0;
        let byteOffset = Math.trunc(bitOffset / 8);
        const [type, val] = yield byteOffset;
        try {
            switch (type) {  // TODO replace with Symbols
                case 's16':
                    if (typeof val !== 'number') throw Error(`Token value mismatch ${type} vs ${typeof val}`);
                    // Currently all s16 values are byte aligned, no shifting required
                    len = 16;
                    view.setInt16(byteOffset, val);
                    break;
                case 'u8':
                    if (typeof val !== 'number') throw Error(`Token value mismatch ${type} vs ${typeof val}`);
                    // Currently all u8 values are byte aligned, no shifting required
                    len = 8;
                    view.setUint8(byteOffset, val);
                    break;
                case 'u16':
                    if (typeof val !== 'number') throw Error(`Token value mismatch ${type} vs ${typeof val}`);
                    // Currently all u16 values are byte aligned, no shifting required
                    len = 16;
                    view.setUint16(byteOffset, val);
                    break;
                case 'u32':
                    if (typeof val !== 'number') throw Error(`Token value mismatch ${type} vs ${typeof val}`);
                    // Currently all u32 values are byte aligned, no shifting required
                    len = 32;
                    view.setUint32(byteOffset, val);
                    break;
                case 'u48':
                    if (!['number', 'bigint'].includes(typeof val)) throw Error(`Token value mismatch ${type} vs ${typeof val}`);
                    // Currently all u48 values are byte aligned, no shifting required
                    len = 48;
                    view.setUint16(byteOffset, Number(BigInt(val as number) >> 32n));
                    view.setUint32(byteOffset+2, Number(BigInt(val as number) & 0xFFFFFFFFn));
                    break;
                case 'u3':
                    // Only used by header Z field, no-op
                    len = 3;
                    break;
                case 'u15':
                    // Used by OPT Z field, no-op
                    len = 15;
                    break;
                case 'u2':
                    if (typeof val !== 'number') throw Error(`Token value mismatch ${type} vs ${typeof val}`);
                    bigval = view.getUint16(byteOffset);
                    bigval |= val << (13 - (bitOffset % 8));
                    len = 2;
                    view.setUint16(byteOffset, bigval);
                    break;
                case 'u4':
                    if (typeof val !== 'number') throw Error(`Token value mismatch ${type} vs ${typeof val}`);
                    bigval = view.getUint16(byteOffset);
                    bigval |= val << (11 - (bitOffset % 8));
                    len = 4;
                    view.setUint16(byteOffset, bigval);
                    break;
                case 'bit':
                    if (typeof val !== 'number') throw Error(`Token value mismatch ${type} vs ${typeof val}`);
                    let byte = view.getUint8(byteOffset);
                    byte |= val << (7 - (bitOffset % 8));
                    len = 1;
                    view.setUint8(byteOffset, byte);
                    break;
                case 'string[*]': // Write remainder of data as string
                    if (typeof val !== 'string') throw Error(`Token value mismatch ${type} vs ${typeof val}`);
                    if (val.length < view.byteLength - byteOffset) {
                        for (; len < val.length; ++len) {
                            view.setUint8(byteOffset + len, val.charCodeAt(len));
                        }
                    }
                    return;
                case 'string': // Length prefixed string
                    if (typeof val !== 'string') throw Error(`Token value mismatch ${type} vs ${typeof val}`);
                    len = (val.length + 1) * 8;
                    setString(new DataView(data, byteOffset, val.length + 1), val);
                    break;
                case 'string[]': // Array of length prefixed strings, zero terminated or until end of data
                    if (!Array.isArray(val)) throw Error(`Token value mismatch ${type} vs ${typeof val}`);
                    for (const str of val) {
                        if (typeof str !== 'string') throw Error(`Token value mismatch 'string' vs ${typeof str}`);
                        len += (str.length + 1) * 8;
                        setString(new DataView(data, byteOffset, str.length + 1), str);
                        byteOffset += str.length + 1;
                    }
                    if (val[val.length - 1].length !== 0) { // Zero terminate if last element of val not empty
                        len += 8;
                        view.setUint8(byteOffset, 0);
                    }
                    break;
                case 'opaque':
                    if (val instanceof ArrayBuffer) {
                        len += val.byteLength * 8;
                        new Uint8Array(val).forEach((v, i) => view.setUint8(byteOffset + i, v));
                    } else {
                        throw new TypeError("opaque value must be Uint8Array");
                    }
                    break;
                default:
                    throw Error(`Unknown token type: ${type}`);
            }
        } catch (e) {
            if (e instanceof RangeError) {
                throw new RangeError(`Buffer overflow, tried to write ${len}b/${len / 8}B at offset ${bitOffset}b/${byteOffset}B with ${view.byteLength - byteOffset}B remaining`, {cause: e});
            }
            throw e;
        }
    }
    return;
}