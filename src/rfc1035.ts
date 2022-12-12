import {RecordType} from "./constants.js";
import RDATA, {RDATA as RDATATypes} from "./rfc_rdata.js"

export interface Header {
    ID: number,
    QR: 0|1,
    Opcode: 0|1|2|4|5,
    AA: 0|1,
    TC: 0|1,
    RD: 0|1,
    RA: 0|1,
    Z?: undefined,
    AD: 0|1,
    CD: 0|1,
    RCODE?: 0|1|2|3|4|5|6|7|8|9|10|16|17|18|19|20|21|22, // TODO create enum https://www.rfc-editor.org/rfc/rfc6895.html#section-2.3
    QDCOUNT: number,
    ANCOUNT?: number,
    NSCOUNT?: number,
    ARCOUNT?: number,
}

const header = {
    ID: 'u16',  // A 16 bit identifier assigned by the program that
                // generates any kind of query.  This identifier is copied
                // the corresponding reply and can be used by the requester
                // to match up replies to outstanding queries.

    QR: 'bit',  // A one bit field that specifies whether this message is a
                // query (0), or a response (1).

    Opcode: 'u4',   // https://www.rfc-editor.org/rfc/rfc6895.html#section-2.2
                    // A four bit field that specifies kind of query in this
                    // message.  This value is set by the originator of a query
                    // and copied into the response.  The values are:
                    // 0               a standard query (QUERY)
                    // 1               an inverse query (IQUERY)
                    // 2               a server status request (STATUS)
                    // 3               Unassigned
                    // 4               Notify https://www.rfc-editor.org/rfc/rfc1996
                    // 5               Update https://www.rfc-editor.org/rfc/rfc2136
                    // 6-15            reserved for future use

    AA: 'bit',  // Authoritative Answer - this bit is valid in responses,
                // and specifies that the responding name server is an
                // authority for the domain name in question section.
                //
                // Note that the contents of the answer section may have
                // multiple owner names because of aliases.  The AA bit
                // corresponds to the name which matches the query name, or
                // the first owner name in the answer section.

    TC: 'bit',  // Truncation - specifies that this message was truncated
                // due to length greater than that permitted on the
                // transmission channel.

    RD: 'bit',  // Recursion Desired - this bit may be set in a query and
                // is copied into the response.  If RD is set, it directs
                // the name server to pursue the query recursively.
                //     Recursive query support is optional.

    RA: 'bit',  // Recursion Available - this be is set or cleared in a
                // response, and denotes whether recursive query support is
                // available in the name server.

    Z: 'bit',   // Reserved for future use.  Must be zero in all queries
                // and responses. https://www.rfc-editor.org/rfc/rfc6895.html#section-2

    AD: 'bit',  // Authenticated data, used by DNSSEC
    CD: 'bit',  // Checking Disabled, used by DNSSEC

    RCODE: 'u4',// https://www.rfc-editor.org/rfc/rfc6895.html#section-2.3
                // Response code - this 4 bit field is set as part of
                // responses.  The values have the following
                // interpretation:
                //
                // 0               No error condition
                //
                // 1               Format error - The name server was
                //                 unable to interpret the query.
                //
                // 2               Server failure - The name server was
                //                 unable to process this query due to a
                //                 problem with the name server.
                //
                // 3               Name Error - Meaningful only for
                //                 responses from an authoritative name
                //                 server, this code signifies that the
                //                 domain name referenced in the query does
                //                 not exist.
                //
                // 4               Not Implemented - The name server does
                //                 not support the requested kind of query.
                //
                // 5               Refused - The name server refuses to
                //                 perform the specified operation for
                //                 policy reasons.  For example, a name
                //                 server may not wish to provide the
                //                 information to the particular requester,
                //                 or a name server may not wish to perform
                //                 a particular operation (e.g., zone
                // transfer) for particular data.
                //
                // 6-15            Reserved for future use.

    QDCOUNT: 'u16',// an unsigned 16 bit integer specifying the number of
                   // entries in the question section.

    ANCOUNT: 'u16',// an unsigned 16 bit integer specifying the number of
                   // resource records in the answer section.

    NSCOUNT: 'u16',// an unsigned 16 bit integer specifying the number of name
                   // server resource records in the authority records
                   // section.

    ARCOUNT: 'u16',// an unsigned 16 bit integer specifying the number of
                   // resource records in the additional records section.
} as Record<keyof Header, TokenType>;

const HeaderLen = 12; // bytes

export enum CLASS {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
}

export class Question {
    QNAME: string[];
    QTYPE: RecordType;
    QCLASS: CLASS | 255; // TODO create enum
    constructor(QNAME: string[], QTYPE: RecordType, QCLASS: CLASS|255 = CLASS.IN) {
        this.QNAME = QNAME;
        this.QTYPE = QTYPE;
        this.QCLASS = QCLASS;
    }
}

export const question = {
    QNAME: 'string[]',  // a domain name represented as a sequence of labels, where
                        // each label consists of a length octet followed by that
                        // number of octets.  The domain name terminates with the
                        // zero length octet for the null label of the root.  Note
                        // that this field may be an odd number of octets; no
                        // padding is used.

    QTYPE: 'u16',   // a two octet code which specifies the type of the query.
                    // The values for this field include all codes valid for a
                    // TYPE field, together with some more general codes which
                    // can match more than one type of RR.

    QCLASS: 'u16',  // a two octet code that specifies the class of the query.
                    // For example, the QCLASS field is IN for the Internet.
} as Record<keyof Question, TokenType>;

export interface ResponseRecord<T extends keyof RDATATypes> {
    NAME: string[],
    TYPE: T,
    CLASS: CLASS,
    TTL: number,
    RDLENGTH: number,
    RDATA?: RDATATypes[T],
    raw_rdata?: ArrayBuffer,
}

export type AnswerRecord<T extends keyof RDATATypes> = ResponseRecord<T>;
export type AuthorityRecord<T extends keyof RDATATypes> = ResponseRecord<T>;
export type AdditionalRecord<T extends keyof RDATATypes> = ResponseRecord<T>;

export const record = {
    NAME: 'string[]', // a domain name to which this resource record pertains.

    TYPE: 'u16',    // two octets containing one of the RR type codes.  This
                    // field specifies the meaning of the data in the RDATA
                    // field.

    CLASS: 'u16',   // two octets which specify the class of the data in the
                    // RDATA field.

    TTL: 'u32',     // a 32 bit unsigned integer that specifies the time
                    // interval (in seconds) that the resource record may be
                    // cached before it should be discarded.  Zero values are
                    // interpreted to mean that the RR can only be used for the
                    // transaction in progress, and should not be cached.
    RDLENGTH: 'u16',// an unsigned 16 bit integer that specifies the length in
                    // octets of the RDATA field.

//  RDATA              a variable length string of octets that describes the
//                     resource.  The format of this information varies
//                     according to the TYPE and CLASS of the resource record.
//                     For example, the if the TYPE is A and the CLASS is IN,
//                     the RDATA field is a 4 octet ARPA Internet address.
} as Record<keyof Omit<ResponseRecord<any>, "RDATA">, TokenType>;

export interface Edns0Opt {
    NAME: string[],
    TYPE: RecordType.OPT,
    UDPPAYLOADSIZE: number,
    ERCODE: number,
    VERSION: 0,
    DO: number,
    Z: undefined,
    RDLENGTH: number,
    RDATA?: any,
}
export let UDPPAYLOADSIZE = 4096;

const edns0Opt = {
    // https://datatracker.ietf.org/doc/html/rfc2671
    NAME: 'string[]', // empty (root domain)

    TYPE: 'u16',  // OPT

    UDPPAYLOADSIZE: 'u16',  // sender's UDP payload size

    ERCODE: 'u8',   // EXTENDED-RCODE  Forms upper 8 bits of extended 12-bit RCODE.  Note
                    // that EXTENDED-RCODE value "0" indicates that an
                    // unextended RCODE is in use (values "0" through "15").

    VERSION: 'u8',  // Indicates the implementation level of whoever sets
                    // it.  Full conformance with this specification is
                    // indicated by version "0."  Requestors are encouraged
                    // to set this to the lowest implemented level capable
                    // of expressing a transaction, to minimize the
                    // responder and network load of discovering the
                    // greatest common implementation level between
                    // requestor and responder.  A requestor's version
                    // numbering strategy should ideally be a run time
                    // configuration option.
                    // If a responder does not implement the VERSION level
                    // of the request, then it answers with RCODE=BADVERS.
                    // All responses will be limited in format to the
                    // VERSION level of the request, but the VERSION of each
                    // response will be the highest implementation level of
                    // the responder.  In this way a requestor will learn
                    // the implementation level of a responder as a side
                    // effect of every response, including error responses,
                    // including RCODE=BADVERS.

    DO: 'bit',  // Setting the DO bit to one in a query indicates to the server that the
                // resolver is able to accept DNSSEC security RRs.  The DO bit cleared
                // (set to zero) indicates the resolver is unprepared to handle DNSSEC
                // security RRs and those RRs MUST NOT be returned in the response
                // (unless DNSSEC security RRs are explicitly queried for).  The DO bit
                // of the query MUST be copied in the response.
                // https://datatracker.ietf.org/doc/html/rfc3225

    Z: 'u15',   // Set to zero by senders and ignored by receivers,
                // unless modified in a subsequent specification.

    RDLENGTH: 'u16',  // an unsigned 16 bit integer that specifies the length in
                      // octets of the RDATA field.
} as Record<keyof Edns0Opt, TokenType>;

const Edns0OptLen = 11;

export type TokenType = 's16'|'u8'|'u16'|'string'|'u32'|'string[]'|'string[*]'|string|'u3'|'u4'|'bit'|'opaque'|number;
export type TokenVal = number|string|string[]|ArrayBuffer|undefined|DataView;
export type Tokenizer = Generator<TokenVal, undefined, TokenType>;

/**
 * Deserialize binary RFC1035 wire format
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
                    len = parseInt((type as string).substring(7, (type as string).length-1), 10);
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
 * Serialize binary RFC1035 wire format
 * Returns a Generator that accepts tuples of ('s16'|'u8'|'u16'|'string'|'u32'|'string[]'|'string[*]'|'u3'|'u4'|'bit'|'u15'|'opaque', number|string|string[]|ArrayBuffer) as a parameter
 * The generator will convert the second tuple value to the binary representation specified in the first tuple value
 * @param data buffer to populate
 */
export function* serialize(data: ArrayBuffer): Generator<number, undefined, [TokenType, TokenVal]> {
    const view = new DataView(data);
    let len = 0;
    for (let bitOffset = 0; bitOffset < view.byteLength * 8; bitOffset += len) {
        len = 0;
        let byteOffset = Math.trunc(bitOffset / 8);
        const [type, val] = yield byteOffset;
        switch (type) {  // TODO replace with Symbols
            case 's16':
                if (typeof val !== 'number') throw Error(`Token value mismatch ${type} vs ${typeof val}`);
                view.setInt16(byteOffset, val);
                // Currently all s16 values are byte aligned, no shifting required
                len = 16;
                break;
            case 'u8':
                if (typeof val !== 'number') throw Error(`Token value mismatch ${type} vs ${typeof val}`);
                view.setUint8(byteOffset, val);
                // Currently all u8 values are byte aligned, no shifting required
                len = 8;
                break;
            case 'u16':
                if (typeof val !== 'number') throw Error(`Token value mismatch ${type} vs ${typeof val}`);
                view.setUint16(byteOffset, val);
                // Currently all u16 values are byte aligned, no shifting required
                len = 16;
                break;
            case 'u32':
                if (typeof val !== 'number') throw Error(`Token value mismatch ${type} vs ${typeof val}`);
                view.setUint32(byteOffset, val);
                // Currently all u32 values are byte aligned, no shifting required
                len = 32;
                break;
            case 'u3':
                // Only used by header Z field, no-op
                len = 3;
                break;
            case 'u15':
                // Used by OPT Z field, no-op
                len = 15;
                break;
            case 'u4':
                if (typeof val !== 'number') throw Error(`Token value mismatch ${type} vs ${typeof val}`);
                let bigval = view.getUint16(byteOffset);
                bigval |= val << (11 - (bitOffset % 8));
                view.setUint16(byteOffset, bigval);
                len = 4;
                break;
            case 'bit':
                if (typeof val !== 'number') throw Error(`Token value mismatch ${type} vs ${typeof val}`);
                let byte = view.getUint8(byteOffset);
                byte |= val << (7 - (bitOffset % 8));
                view.setUint8(byteOffset, byte);
                len = 1;
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
                setString(new DataView(data, byteOffset, val.length+1), val);
                len = (val.length + 1) * 8;
                break;
            case 'string[]': // Array of length prefixed strings, zero terminated or until end of data
                if (!Array.isArray(val)) throw Error(`Token value mismatch ${type} vs ${typeof val}`);
                for (const str of val) {
                    if (typeof str !== 'string') throw Error(`Token value mismatch 'string' vs ${typeof str}`);
                    setString(new DataView(data, byteOffset, str.length+1), str);
                    byteOffset += str.length + 1;
                    len += (str.length + 1) * 8;
                }
                if (val[val.length-1].length !== 0) { // Zero terminate if last element of val not empty
                    view.setUint8(byteOffset, 0);
                    len += 8;
                }
                break;
            case 'opaque':
                if (val instanceof Uint8Array) {
                    val.forEach((v, i)=>view.setUint8(byteOffset + i, v));
                    len += val.length * 8;
                }
                break;
            default:
                throw Error(`Unknown token type: ${type}`);
        }
    }
    return;
}

/**
 * Build DNS wireformat request
 * @param questions Questions to include in request
 * @param recursive Set the RD bit of the DNS request
 * @param dnssec Enable client side DNSSEC validation
 */
export function buildRequest(questions: Question[], recursive: boolean = true, dnssec: boolean = false): ArrayBuffer {
    const additional: AdditionalRecord<keyof RDATATypes>[] = [];
    let totalLen = HeaderLen;
    if (dnssec) {
        totalLen += Edns0OptLen;
        additional.push({NAME: [''], TYPE: RecordType.OPT, UDPPAYLOADSIZE, VERSION: 0, ERCODE: 0, DO: 1, RDLENGTH: 0, Z: undefined} as Edns0Opt as unknown as AdditionalRecord<RecordType.OPT>)
    }

    totalLen += (questions.length * 4) // Bytes for QTYPE+QCLASS
    + questions.reduce((acc, q)=>acc + q.QNAME.length + q.QNAME.reduce((a,c)=>a+c.length, 0) + ( q.QNAME[q.QNAME.length-1].length === 0 ? 0 : 1 ), 0); // Bytes required for QNAMEs

    const buf = new ArrayBuffer(totalLen);
    const encoder = serialize(buf);
    encoder.next();
    const head = {ID: 0, QR: 0, Opcode: 0, AA: 0, TC: 0, RD: recursive ? 1 : 0, QDCOUNT: questions.length, ARCOUNT: dnssec?1:0} as Header;
    for (const [token, type] of Object.entries(header) as [keyof Header, TokenType][]) encoder.next([type, head[token] || 0]);
    for (const q of questions) {
        for (const [token, type] of Object.entries(question) as [keyof Question, TokenType][]) encoder.next([type, q[token]]);
    }
    for (const a of additional) {
        let tokens;
        switch (a.TYPE) {
            case RecordType.OPT:
                tokens = Object.entries(edns0Opt);
                break;
            default:
                tokens = Object.entries(question);
                break;
        }
        for (const [token, type] of tokens as [keyof Omit<ResponseRecord<any>, "RDATA">, TokenType][]) encoder.next([type, a[token] as TokenVal]);
    }

    return buf;
}

export interface Response {
    header: Header,
    question: Question[],
    answer: AnswerRecord<keyof RDATATypes>[],
    authority: AuthorityRecord<keyof RDATATypes>[],
    additional: AdditionalRecord<keyof RDATATypes>[],
}

/**
 * Parse DNS wire format response
 * @param data DNS response data in wire format
 * @param keepRDATA include a 'raw_rdata' property in the ResponseRecords that holds a copy of the wire-formatted RDATA
 */
export function parseResponse(data: ArrayBuffer, keepRDATA: boolean = false): Response {
    const decoder = deserialize(data);
    decoder.next();
    const response: Response = {header: {} as Header, question: [], answer: [], authority: [], additional: []};
    // Header
    for (const [token, type] of Object.entries(header) as [keyof Header, TokenType][]) (response.header[token] as TokenVal) = decoder.next(type).value;

    // Question[]
    for (let i = 0; i < response.header.QDCOUNT; ++i) {
        const q: Question = {} as Question;
        for (const [token, type] of Object.entries(question) as [keyof Question, TokenType][]) (q[token] as TokenVal) = decoder.next(type).value;
        response.question.push(q);
    }

    // answer, authority, additional
    for (const [count, category] of [[response.header.ANCOUNT, response.answer], [response.header.NSCOUNT, response.authority], [response.header.ARCOUNT, response.additional]]) {
        for (let i = 0; i < count; ++i) {
            const r: ResponseRecord<keyof RDATATypes> | Edns0Opt = {} as ResponseRecord<keyof RDATATypes>;
            let tokens = Object.entries(record);
            while (Object.keys(r).length < tokens.length) {
                for (const [token, type] of tokens as [keyof Omit<ResponseRecord<any>, "RDATA">, TokenType][]) {
                    if (token in r) continue; // Skip existing keys if looping back around from break
                    (r[token] as TokenVal) = decoder.next(type).value;
                    if (token === 'TYPE' && r[token] === RecordType.OPT) {
                        tokens = Object.entries(edns0Opt);
                        break;
                    }
                }
            }
            if ('ERCODE' in r) {
                response.header.RCODE |= (r as unknown as Edns0Opt).ERCODE << 4;
            }
            if (r.RDLENGTH > 0) {
                const byteOffset = decoder.next().value as number || 0;
                const end = byteOffset + r.RDLENGTH;
                if (end > data.byteLength) throw Error(`RDLENGTH extends past end of received data`);
                decoder.next(r.RDLENGTH); // Advance by RDLENGTH
                const rdataDecoder = deserialize(data, byteOffset, end);
                rdataDecoder.next();
                r.RDATA = RDATA<any>(rdataDecoder, r.TYPE);
                r.raw_rdata = keepRDATA ? data.slice(byteOffset, end) : undefined;
            } else {
                r.RDATA = null;
            }
            (category as ResponseRecord<keyof RDATATypes>[]).push(r);
        }
    }
    if (!decoder.next().done as boolean) throw Error(`Received data longer than expected`);
    return response;
}
