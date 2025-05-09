import * as constants from "./constants.js";
import {CLASS, RecordType, RCode} from "./constants.js";
import RDATA, {RDATA as RDATATypes} from "./rfc_rdata.js"
import {DNSError, ResolveOptions} from "./dns.js";
import {BaseResolver} from "./base_resolver.js";
import validate from "./rfc4034.js";
import {toNodeJSResponse} from "./nodejs.js";
import {base64url_encode} from "./base64url.js";
import {TokenType, TokenVal, serialize, deserialize} from "./bin_util.js";

const CACHE_NAME = '@i2labs.ca/dns';

/**
 * Calculate the byte length of a domain name in wire format.
 * This will handle domain names with a trailing empty string.
 * @param name String of strings containing domain name components
 */
export function domainNameLen(name: string[]): number {
    return name.length + name.reduce((a, c) => a + c.length, 0) + (name[name.length - 1].length === 0 ? 0 : 1);
}

// eslint-disable:no-bitwise
export interface Header {
    ID: number,
    QR: 0 | 1,
    Opcode: 0 | 1 | 2 | 4 | 5,
    AA: 0 | 1,
    TC: 0 | 1,
    RD: 0 | 1,
    RA: 0 | 1,
    Z?: undefined,
    AD: 0 | 1,
    CD: 0 | 1,
    RCODE?: RCode,
    QDCOUNT: number,
    ANCOUNT?: number,
    NSCOUNT?: number,
    ARCOUNT?: number,
}

const header = {
    // https://www.rfc-editor.org/rfc/rfc6895.html#section-2
    // https://www.rfc-editor.org/rfc/rfc2136#section-2
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

    RA: 'bit',  // Recursion Available - this bit is set or cleared in a
                // response, and denotes whether recursive query support is
                // available in the name server.

    Z: 'bit',   // Reserved for future use.  Must be zero in all queries
                // and responses. https://www.rfc-editor.org/rfc/rfc6895.html#section-2

    AD: 'bit',  // Authenticated data, used by DNSSEC
                // https://www.rfc-editor.org/rfc/rfc6840#section-5.7

    CD: 'bit',  // Checking Disabled, used by DNSSEC
                // https://www.rfc-editor.org/rfc/rfc6840#section-5.9

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

export class Question {
    QNAME: string[];
    QTYPE: RecordType;
    QCLASS: CLASS | 255; // TODO create enum
    constructor(QNAME: string[], QTYPE: RecordType, QCLASS: CLASS | 255 = CLASS.IN) {
        this.QNAME = QNAME;
        this.QTYPE = QTYPE;
        this.QCLASS = QCLASS;
    }

    static equals(q1: Question, q2: Question) {
        return q1.QNAME.length === q2.QNAME.length &&
            q1.QNAME.every((v, i) => v === q2.QNAME[i]) &&
            q1.QTYPE === q2.QTYPE &&
            q1.QCLASS === q2.QCLASS;
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

// eslint-disable-next-line prefer-const
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
        additional.push({
            NAME: [''],
            TYPE: RecordType.OPT,
            UDPPAYLOADSIZE,
            VERSION: 0,
            ERCODE: 0,
            DO: 1,
            RDLENGTH: 0,
            Z: undefined
        } as Edns0Opt as unknown as AdditionalRecord<RecordType.OPT>)
    }

    totalLen += (questions.length * 4) // Bytes for QTYPE+QCLASS
        + questions.reduce((acc, q) => acc + domainNameLen(q.QNAME), 0); // Bytes required for QNAMEs

    const buf = new ArrayBuffer(totalLen);
    const encoder = serialize(buf);
    encoder.next();
    const head = {
        // https://www.rfc-editor.org/rfc/rfc6895.html#section-2
        // https://www.rfc-editor.org/rfc/rfc2136#section-2
        ID: Date.now() % (2 ** 16),
        QR: 0,
        Opcode: 0,
        AA: 0,
        TC: 0,
        RD: recursive !== false ? 1 : 0,
        QDCOUNT: questions.length,
        ARCOUNT: dnssec ? 1 : 0
    } as Header;
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

export interface DNSResponse {
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
export function parseResponse(data: ArrayBuffer, keepRDATA: boolean = false): DNSResponse {
    const decoder = deserialize(data);
    decoder.next();
    const response: DNSResponse = {header: {} as Header, question: [], answer: [], authority: [], additional: []};
    // Header
    for (const [token, type] of Object.entries(header) as [keyof Header, TokenType][]) (response.header[token] as TokenVal) = decoder.next(type).value;

    // Question[]
    for (let i = 0; i < response.header.QDCOUNT; ++i) {
        const q: Question = {} as Question;
        for (const [token, type] of Object.entries(question) as [keyof Question, TokenType][]) (q[token] as TokenVal) = decoder.next(type).value;
        response.question.push(q);
    }

    // answer, authority, additional
    for (const [count, category] of [[response.header.ANCOUNT, response.answer], [response.header.NSCOUNT, response.authority], [response.header.ARCOUNT, response.additional]] as [number, ResponseRecord<any>[]][]) {
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
                if (end > data.byteLength) throw new DNSError(`RDLENGTH extends past end of received data`, constants.BADRESP);
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
    if (!decoder.next().done as boolean) throw new DNSError(`Received data longer than expected`, constants.BADRESP);
    return response;
}

// eslint-disable-next-line:max-classes-per-file
export abstract class WireFormatResolver extends BaseResolver {
    private _pending: Set<AbortController> = new Set();

    abstract _submit(server: string, request: ArrayBuffer, keepRDATA: boolean, abortSignal: AbortSignal): Promise<[DNSResponse, ArrayBuffer]>;

    protected _url(server: string, payload: string) {
        return `https://${server}/dns-query?dns=${payload}`;
    }

    resolve(hostname: string | {
        hostname: string,
        rrtype: (keyof typeof RecordType)
    }[], rrtype?: (keyof typeof RecordType) | "ANY" | ResolveOptions, options?: ResolveOptions): Promise<any | any[]> {
        let questions: Question[];
        if (!Array.isArray(hostname)) {
            if (rrtype === "ANY") rrtype = "*";
            else if (rrtype === undefined) rrtype = 'A';
            questions = [new Question(hostname.split('.'), RecordType[rrtype as keyof typeof RecordType])];
        } else {
            questions = hostname.map(q => new Question(q.hostname.split('.'), RecordType[q.rrtype as keyof typeof RecordType]));
        }
        const request = buildRequest(questions, options && options.recursive, options && options.dnssec);

        let response: DNSResponse;
        const errors: Error[] = [];

        // This must be done synchronously with the call to resolve() or cancel() will race if called soon after
        const controller = new AbortController();
        this._pending.add(controller);

        return (async () => {
            // Retry request with timeout
            let id;
            success: for (let _try = this._tries; _try > 0; --_try) {
                let timeout = false;
                if (id) clearTimeout(id);
                if (this._timeout !== -1) id = setTimeout(() => {
                    timeout = true;
                    controller.abort();
                }, this._timeout);
                for (const server of this.getServers()) {
                    // Check cached records
                    const payload = base64url_encode(request);
                    const url = this._url(server, payload);
                    const cache = await caches.open(CACHE_NAME);
                    let rawResponse = await cache.match(url);
                    if (rawResponse) {
                        const expires = rawResponse.headers.get('Expires');
                        if (!expires || new Date(expires) < new Date()) {
                            cache.delete(url);
                            rawResponse = null;
                        }
                    }

                    try {
                        let rawData: ArrayBuffer;
                        [response, rawData] = await this._submit(server, request, options && options.dnssec, controller.signal);
                        if (response.header.RCODE !== RCode.NoError) throw DNSError.fromRCode(response.header.RCODE);
                        // eslint-disable-next-line:no-console
                        console.log(`"${rrtype}": "${base64url_encode(rawData)}"`);
                        if (response.question) { // verify questions
                            if (response.question.length !== questions.length) throw new Error('DNS query in response does not match original query');
                            verifyQ: for (const reqQ of questions) {
                                // Yes, this is O(n^2) but n is so small I am not sure if the time to copy response.question
                                // array is worth it given it is likely that the questions be returned in the same
                                // order as requested
                                for (const respQ of response.question)
                                    if (Question.equals(reqQ, respQ)) continue verifyQ;
                                throw new Error('DNS query in response does not match original query');
                            }
                        } else throw new Error('Unable to validate DNS query from response');

                        // verify DNSSEC
                        if (options && options.dnssec && !await validate(response, this)) throw new Error(`DNSSEC validation for ${rrtype} from ${hostname} failed`);

                        // Cache response with expires set to the smallest record TTL
                        const minTTL = response.answer.reduce((acc, cur) => acc > cur.TTL ? cur.TTL : acc, 700000); // Max TTL is 604800
                        if (minTTL <= 604800) {
                            rawResponse = new Response(rawData, {
                                status: 200,
                                headers: {
                                    Expires: new Date(Date.now() + (minTTL * 1000)).toUTCString(),
                                },
                            });
                            cache.put(url, rawResponse);
                        }

                        break success;
                    } catch (e) {
                        let error = e;
                        // eslint-disable-next-line:no-console
                        console.error(e);
                        if (e.name === 'AbortError') {
                            if (timeout) error = DNSError.TIMEOUT;
                            else error = DNSError.CANCELLED;
                        }
                        if (!(e instanceof DNSError)) {
                            // TODO translate e to DNSErrors
                            switch (error.name) {
                                case '':

                            }
                        }
                        errors.push(error);
                        if (_try > 0) continue;
                    }
                }
            }
            if (id) clearTimeout(id);
            this._pending.delete(controller);
            if (!response) {
                if (errors.length === 1) throw errors[0];
                else throw new AggregateError(errors);
            }

            if (options && options.raw) return response;

            if (!response.answer || response.answer.length === 0) throw DNSError.NODATA;
            return toNodeJSResponse(response.answer, rrtype as string, options);
        })();
    }

    public cancel(): void {
        for (const controller of this._pending) controller.abort();
        this._pending.clear();
    }
}