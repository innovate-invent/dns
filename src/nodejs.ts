import {AnswerRecord} from "./rfc1035";
import {RecordType} from "./constants";
import {RDATA} from "./rfc_rdata";
import {
    AnyAAAARecord,
    AnyARecord, AnyCAARecord,
    AnyCNAMERecord, AnyMXRecord,
    AnyNAPTRRecord,
    AnyNSRecord,
    AnyPTRRecord,
    AnySOARecord, AnySRVRecord, AnyTXTRecord, CAARecord, MXRecord, NAPTRRecord, ResolveOptions, SRVRecord
} from "./dns";

/**
 * Convert A or AAAA IP addresses to string, with IP6 shortening convention
 * @param type RecordType.A or RecordType.AAAA
 * @param ip Array of IP4 or IP6 numbers
 */
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

/**
 * Convert dns response answers to NodeJS dns lib compatibility return values
 * @param answer DNS Response answer records
 * @param rrtype Query rrtype
 * @param options Resolve options
 */
export function toNodeJSResponse(answer: AnswerRecord<any>[], rrtype: string, options?: ResolveOptions): any {
    let rrset = answer.filter(r => r.TYPE !== RecordType.RRSIG);
    if (rrtype in RecordType) {
        rrset = answer.filter(r => r.TYPE === RecordType[rrtype as unknown as RecordType]);
    }

    switch (rrtype) {
        case 'A':
        case 'AAAA':
            if (options && options.ttl) return rrset.map((item: AnswerRecord<RecordType.A|RecordType.AAAA>) => ({
                type: rrtype,
                address: ipString(item.TYPE, item.RDATA),
                ttl: item.TTL
            }));
            return rrset.map((item: AnswerRecord<RecordType.A|RecordType.AAAA>) => ipString(item.TYPE, item.RDATA));
        default:
        case 'CNAME':
        case 'NS':
        case 'PTR':
            return rrset.map((item: AnswerRecord<RecordType.CNAME|RecordType.NS|RecordType.PTR>) => item.RDATA.join ? item.RDATA.filter((i: any) => !!i).join('.') : item.RDATA);
        case '*':
            return rrset.map((item: AnswerRecord<keyof RDATA>) => {
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
            return rrset.map((item: AnswerRecord<RecordType.MX>) => ({
                exchange: item.RDATA.EXCHANGE.filter((x: string) => !!x).join('.'),
                priority: item.RDATA.PREFERENCE
            } as MXRecord));
        case 'NAPTR':
            return rrset.map((item: AnswerRecord<RecordType.NAPTR>) => ({
                flags: item.RDATA.FLAGS,
                order: item.RDATA.ORDER,
                preference: item.RDATA.PREFERENCE,
                regexp: item.RDATA.REGEXP,
                replacement: item.RDATA.REPLACEMENT.filter((x: string) => !!x).join('.'),
                service: item.RDATA.SERVICES
            } as NAPTRRecord));
        case 'SOA':
            return rrset.map((item: AnswerRecord<RecordType.SOA>) => ({
                minttl: item.RDATA.MINIMUM,
                expire: item.RDATA.EXPIRE,
                retry: item.RDATA.RETRY,
                refresh: item.RDATA.REFRESH,
                serial: item.RDATA.SERIAL,
                hostmaster: item.RDATA.RNAME.filter((x: string) => !!x).join('.'),
                nsname: item.RDATA.MNAME.filter((x: string) => !!x).join('.')
            } as AnySOARecord))[0];
        case 'SRV':
            return rrset.map((item: AnswerRecord<RecordType.SRV>) => ({
                weight: item.RDATA.weight,
                priority: item.RDATA.priority,
                name: item.RDATA.target.filter((x: string) => !!x).join('.'),
                port: item.RDATA.port
            } as SRVRecord));
        case 'TXT':
            return rrset.map(item => item.RDATA);
        case 'CAA':
            return rrset.filter(item => item.TYPE === RecordType.CAA).map((item: AnswerRecord<RecordType.CAA>) => ({
                critical: item.RDATA.flags,
                [item.RDATA.tag]: item.RDATA.value
            } as CAARecord));
    }
}