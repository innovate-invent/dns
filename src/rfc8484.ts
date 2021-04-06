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
import {buildRequest, parseResponse, Question} from "./rfc1035.js";

export function base64url_encode(buffer: ArrayBuffer): string {
    return btoa(Array.from(new Uint8Array(buffer), b => String.fromCharCode(b)).join(''))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

export function base64url_decode(value: string): ArrayBuffer {
    const m = value.length % 4;
    return Uint8Array.from(atob(
        value.replace(/-/g, '+')
            .replace(/_/g, '/')
            .padEnd(value.length + (m === 0 ? 0 : 4 - m), '=')
    ), c => c.charCodeAt(0)).buffer
}

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
        const payload = base64url_encode(buildRequest([new Question(hostname.split('.'), RecordType[rrtype as keyof typeof RecordType])]));
        return this._fetch(`https://${this.getServers()[0]}/dns-query?dns=${payload}`, {headers: new Headers({'accept': 'application/dns-message'})})
            .then(response => response.arrayBuffer())
            .then(parseResponse)
            .then(response => {
                if (!response.answer) throw DNSError.NODATA;
                if (options && options.raw) return response;
                switch (rrtype) {
                    case 'A':
                    case 'AAAA':
                        if (options && options.ttl) return response.answer.map(item => ({
                            type: rrtype,
                            address: ipString(item.TYPE, item.RDATA),
                            ttl: item.TTL
                        }));
                        return response.answer.map(item => ipString(item.TYPE, item.RDATA));
                    default:
                    case 'CNAME':
                    case 'NS':
                    case 'PTR':
                        return response.answer.map(item => item.RDATA.join ? item.RDATA.filter((i: any) => !!i).join('.') : item.RDATA);
                    case 'ANY':
                        return response.answer.map(item => {
                            switch (item.TYPE) {
                                case RecordType.A:
                                    return {
                                        type: 'A',
                                        address: ipString(item.TYPE, item.RDATA),
                                        ttl: item.TTL
                                    } as AnyARecord;
                                case RecordType.AAAA:
                                    return {
                                        type: 'AAAA',
                                        address: ipString(item.TYPE, item.RDATA),
                                        ttl: item.TTL
                                    } as AnyAAAARecord;
                                case RecordType.CNAME:
                                    return {type: 'CNAME', value: item.RDATA} as AnyCNAMERecord;
                                case RecordType.NS:
                                    return {type: 'NS', value: item.RDATA} as AnyNSRecord;
                                case RecordType.PTR:
                                    return {type: 'PTR', value: item.RDATA} as AnyPTRRecord;
                                case RecordType.NAPTR:
                                    return {
                                        type: 'NAPTR',
                                        flags: item.RDATA.FLAGS,
                                        order: item.RDATA.ORDER,
                                        preference: item.RDATA.PREFERENCE,
                                        regexp: item.RDATA.REGEXP,
                                        replacement: item.RDATA.REPLACEMENT.filter((x: string) => !!x).join('.'),
                                        service: item.RDATA.SERVICES
                                    } as AnyNAPTRRecord;
                                case RecordType.SOA:
                                    return {
                                        type: 'SOA',
                                        minttl: item.RDATA.MINIMUM,
                                        expire: item.RDATA.EXPIRE,
                                        retry: item.RDATA.RETRY,
                                        refresh: item.RDATA.REFRESH,
                                        serial: item.RDATA.SERIAL,
                                        hostmaster: item.RDATA.RNAME.filter((x: string) => !!x).join('.'),
                                        nsname: item.RDATA.MNAME.filter((x: string) => !!x).join('.')
                                    } as AnySOARecord;
                                case RecordType.MX:
                                    return {
                                        type: 'MX',
                                        exchange: item.RDATA.EXCHANGE.filter((x: string) => !!x).join('.'),
                                        priority: item.RDATA.PREFERENCE
                                    } as AnyMXRecord;
                                case RecordType.TXT:
                                    return {type: 'TXT', entries: item.RDATA} as AnyTXTRecord;
                                case RecordType.CAA:
                                    return {
                                        type: 'CAA',
                                        critical: item.RDATA.flags,
                                        [item.RDATA.tag]: item.RDATA.value
                                    } as AnyCAARecord;
                                case RecordType.SRV:
                                    return {
                                        type: "SRV",
                                        weight: item.RDATA.weight,
                                        priority: item.RDATA.priority,
                                        name: item.RDATA.target.filter((x: string) => !!x).join('.'),
                                        port: item.RDATA.port
                                    } as AnySRVRecord;
                            }
                        });
                    case 'MX':
                        return response.answer.map(item => ({
                            exchange: item.RDATA.EXCHANGE.filter((x: string) => !!x).join('.'),
                            priority: item.RDATA.PREFERENCE
                        } as MXRecord));
                    case 'NAPTR':
                        return response.answer.map(item => ({
                            flags: item.RDATA.FLAGS,
                            order: item.RDATA.ORDER,
                            preference: item.RDATA.PREFERENCE,
                            regexp: item.RDATA.REGEXP,
                            replacement: item.RDATA.REPLACEMENT.filter((x: string) => !!x).join('.'),
                            service: item.RDATA.SERVICES
                        } as NAPTRRecord));
                    case 'SOA':
                        return response.answer.map(item => ({
                            minttl: item.RDATA.MINIMUM,
                            expire: item.RDATA.EXPIRE,
                            retry: item.RDATA.RETRY,
                            refresh: item.RDATA.REFRESH,
                            serial: item.RDATA.SERIAL,
                            hostmaster: item.RDATA.RNAME.filter((x: string) => !!x).join('.'),
                            nsname: item.RDATA.MNAME.filter((x: string) => !!x).join('.')
                        } as AnySOARecord))[0];
                    case 'SRV':
                        return response.answer.map(item => ({
                            weight: item.RDATA.weight,
                            priority: item.RDATA.priority,
                            name: item.RDATA.target.filter((x: string) => !!x).join('.'),
                            port: item.RDATA.port
                        } as SRVRecord));
                    case 'TXT':
                        return response.answer.map(item => item.RDATA);
                    case 'CAA':
                        return response.answer.filter(item => item.TYPE === RecordType.CAA).map(item => ({
                            critical: item.RDATA.flags,
                            [item.RDATA.tag]: item.RDATA.value
                        } as CAARecord));
                }
            });
    }
}
