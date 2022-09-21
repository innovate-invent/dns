/**
 * RFS8484 DoH Resolver
 * https://tools.ietf.org/html/rfc8484
 */

import {BaseResolver} from './base_resolver.js'
import {
    AnyAAAARecord,
    AnyARecord,
    AnyCAARecord,
    AnyCNAMERecord,
    AnyMXRecord,
    AnyNAPTRRecord,
    AnyNSRecord,
    AnyPTRRecord,
    AnySOARecord,
    AnySRVRecord,
    AnyTXTRecord,
    CAARecord,
    DNSError,
    MXRecord,
    NAPTRRecord,
    ResolveOptions,
    SRVRecord,
} from './dns.js'
import {RecordType} from "./constants.js";
import {AnswerRecord, buildRequest, parseResponse, Question, ResponseRecord} from "./rfc1035.js";
import {RDATA} from "./rfc_rdata.js"
import validate from "./rfc4034.js";
import {base64url_encode} from "./base64url.js"

function ipString(type: RecordType, ip: number[]): string {
    if (type === RecordType.A) return ip.map(n => n.toString(10)).join('.');
    else if (type === RecordType.AAAA) {
        // IP6 shortening
        let start = 0;
        let len = 0;
        let longestLen = 0;
        let longestStart = 0;
        for (let i = 0; i < ip.length; ++i) {
            if (ip[i] === 0 && len === 0) {
                start = i;
                ++len;
            } else if (ip[i] !== 0 && len !== 0) {
                if (len > longestLen) {
                    longestLen = len;
                    longestStart = start;
                }
                len = 0;
            } else if (len !== 0) ++len;
        }
        if (longestLen === ip.length || len === ip.length) return '::';
        if (longestLen !== 0 || len !== 0) {
            const ipStr = ip.map(n => n.toString(16));
            return [...ipStr.slice(0, longestStart), '', ...ipStr.slice(longestStart + (longestLen || len))].join(':');
        }
        return ip.map(n => n.toString(16)).join(':');
    }
}

export default class Resolver extends BaseResolver {
    protected servers: string[] = ['cloudflare-dns.com'];

    resolve(hostname: string, rrtype?: (keyof typeof RecordType) | "ANY", options?: ResolveOptions): Promise<any> {
        if (rrtype === "ANY") rrtype = "*";
        else if (rrtype === undefined) rrtype = 'A';
        const question = new Question(hostname.split('.'), RecordType[rrtype as keyof typeof RecordType]);
        const payload = base64url_encode(buildRequest([question], undefined, options && options.dnssec));
        return this._fetch(`https://${this.getServers()[0]}/dns-query?dns=${payload}`, {headers: new Headers({'accept': 'application/dns-message'})})
            .then(response => response.arrayBuffer())
            .then(response => parseResponse(response, options && options.dnssec))
            .then(async response => {
                if (!response.answer) throw DNSError.NODATA;
                if (response.question && response.question.length === 1) { // verify question
                    const q = response.question[0];
                    if (Object.entries(question).some(([k,v])=>Array.isArray(v) ? v.some((e, i)=>e !== (q[k as keyof Question] as any[])[i]) : q[k as keyof Question] !== v)) throw new Error('DNS query in response does not match original query');
                } else throw new Error('Unable to validate DNS query from response');

                if (options && options.dnssec && !await validate(response, this)) throw new Error('DNSSEC validation failed'); // verify DNSSEC
                if (options && options.raw) return response;

                switch (rrtype) {
                    case 'A':
                    case 'AAAA':
                        if (options && options.ttl) return response.answer.map((item: AnswerRecord<RecordType.A|RecordType.AAAA>) => ({
                            type: rrtype,
                            address: ipString(item.TYPE, item.RDATA),
                            ttl: item.TTL
                        }));
                        return response.answer.map((item: AnswerRecord<RecordType.A|RecordType.AAAA>) => ipString(item.TYPE, item.RDATA));
                    default:
                    case 'CNAME':
                    case 'NS':
                    case 'PTR':
                        return response.answer.map((item: AnswerRecord<RecordType.CNAME|RecordType.NS|RecordType.PTR>) => item.RDATA.join ? item.RDATA.filter((i: any) => !!i).join('.') : item.RDATA);
                    case 'ANY':
                        return response.answer.map((item: AnswerRecord<keyof RDATA>) => {
                            let d;
                            switch (item.TYPE as RecordType) {
                                case RecordType.A:
                                    return {
                                        type: 'A',
                                        address: ipString(item.TYPE, item.RDATA as RDATA[RecordType.A]),
                                        ttl: item.TTL
                                    } as AnyARecord;
                                case RecordType.AAAA:
                                    return {
                                        type: 'AAAA',
                                        address: ipString(item.TYPE, item.RDATA as RDATA[RecordType.AAAA]),
                                        ttl: item.TTL
                                    } as AnyAAAARecord;
                                case RecordType.CNAME:
                                    return {type: 'CNAME', value: item.RDATA} as AnyCNAMERecord;
                                case RecordType.NS:
                                    return {type: 'NS', value: item.RDATA} as AnyNSRecord;
                                case RecordType.PTR:
                                    return {type: 'PTR', value: item.RDATA} as AnyPTRRecord;
                                case RecordType.NAPTR:
                                    d = item.RDATA as RDATA[RecordType.NAPTR];
                                    return {
                                        type: 'NAPTR',
                                        flags: d.FLAGS,
                                        order: d.ORDER,
                                        preference: d.PREFERENCE,
                                        regexp: d.REGEXP,
                                        replacement: d.REPLACEMENT.filter((x: string) => !!x).join('.'),
                                        service: d.SERVICES
                                    } as AnyNAPTRRecord;
                                case RecordType.SOA:
                                    d = item.RDATA as RDATA[RecordType.SOA];
                                    return {
                                        type: 'SOA',
                                        minttl: d.MINIMUM,
                                        expire: d.EXPIRE,
                                        retry: d.RETRY,
                                        refresh: d.REFRESH,
                                        serial: d.SERIAL,
                                        hostmaster: d.RNAME.filter((x: string) => !!x).join('.'),
                                        nsname: d.MNAME.filter((x: string) => !!x).join('.')
                                    } as AnySOARecord;
                                case RecordType.MX:
                                    d = item.RDATA as RDATA[RecordType.MX];
                                    return {
                                        type: 'MX',
                                        exchange: d.EXCHANGE.filter((x: string) => !!x).join('.'),
                                        priority: d.PREFERENCE,
                                    } as AnyMXRecord;
                                case RecordType.TXT:
                                    return {type: 'TXT', entries: item.RDATA} as AnyTXTRecord;
                                case RecordType.CAA:
                                    d = item.RDATA as RDATA[RecordType.CAA];
                                    return {
                                        type: 'CAA',
                                        critical: d.flags,
                                        [d.tag]: d.value
                                    } as AnyCAARecord;
                                case RecordType.SRV:
                                    d = item.RDATA as RDATA[RecordType.SRV];
                                    return {
                                        type: "SRV",
                                        weight: d.weight,
                                        priority: d.priority,
                                        name: d.target.filter((x: string) => !!x).join('.'),
                                        port: d.port
                                    } as AnySRVRecord;
                            }
                        });
                    case 'MX':
                        return response.answer.map((item: AnswerRecord<RecordType.MX>) => ({
                            exchange: item.RDATA.EXCHANGE.filter((x: string) => !!x).join('.'),
                            priority: item.RDATA.PREFERENCE
                        } as MXRecord));
                    case 'NAPTR':
                        return response.answer.map((item: AnswerRecord<RecordType.NAPTR>) => ({
                            flags: item.RDATA.FLAGS,
                            order: item.RDATA.ORDER,
                            preference: item.RDATA.PREFERENCE,
                            regexp: item.RDATA.REGEXP,
                            replacement: item.RDATA.REPLACEMENT.filter((x: string) => !!x).join('.'),
                            service: item.RDATA.SERVICES
                        } as NAPTRRecord));
                    case 'SOA':
                        return response.answer.map((item: AnswerRecord<RecordType.SOA>) => ({
                            minttl: item.RDATA.MINIMUM,
                            expire: item.RDATA.EXPIRE,
                            retry: item.RDATA.RETRY,
                            refresh: item.RDATA.REFRESH,
                            serial: item.RDATA.SERIAL,
                            hostmaster: item.RDATA.RNAME.filter((x: string) => !!x).join('.'),
                            nsname: item.RDATA.MNAME.filter((x: string) => !!x).join('.')
                        } as AnySOARecord))[0];
                    case 'SRV':
                        return response.answer.map((item: AnswerRecord<RecordType.SRV>) => ({
                            weight: item.RDATA.weight,
                            priority: item.RDATA.priority,
                            name: item.RDATA.target.filter((x: string) => !!x).join('.'),
                            port: item.RDATA.port
                        } as SRVRecord));
                    case 'TXT':
                        return response.answer.map(item => item.RDATA);
                    case 'CAA':
                        return response.answer.filter(item => item.TYPE === RecordType.CAA).map((item: AnswerRecord<RecordType.CAA>) => ({
                            critical: item.RDATA.flags,
                            [item.RDATA.tag]: item.RDATA.value
                        } as CAARecord));
                }
            });
    }
}
