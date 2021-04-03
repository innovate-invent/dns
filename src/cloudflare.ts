import {BaseResolver} from './base_resolver.js'
import {
    AAAARecord,
    ARecord,
    CAARecord,
    CNAMERecord,
    DNSError,
    DNSRecord,
    NAPTRRecord,
    NSRecord,
    parseCAA, parseLOC,
    parseMX,
    parseNAPTR,
    parseSOA, parseSPF,
    parseSRV, parseSVCB, parseURI,
    PTRRecord,
    SOARecord,
    SRVRecord,
    TXTRecord,
    Response,
} from './dns.js'
import {RecordType} from "./constants.js";


export default class Resolver extends BaseResolver {
    protected servers: string[] = ['cloudflare-dns.com'];

    resolve(hostname: string, rrtype?: "A"|"AAAA"|"CNAME"|"NS"|"PTR"|string): Promise<string[]>;
    resolve(hostname: string, rrtype?: "A", options?:{ttl:true}): Promise<ARecord[]>;
    resolve(hostname: string, rrtype?: "AAAA", options?:{ttl:true}): Promise<AAAARecord[]>;
    resolve(hostname: string, rrtype: "ANY"): Promise<DNSRecord[]>;
    resolve(hostname: string, rrtype: "CAA"): Promise<{ critical: number; iodef?: string; issue?: string }[]>;
    resolve(hostname: string, rrtype: "MX"): Promise<{ priority: number; exchange: string }[]>;
    resolve(hostname: string, rrtype: "NAPTR"): Promise<NAPTRRecord[]>;
    resolve(hostname: string, rrtype: "SOA"): Promise<SOARecord>;
    resolve(hostname: string, rrtype: "SRV"): Promise<SRVRecord[]>;
    resolve(hostname: string, rrtype: "TXT"): Promise<string[][]>;
    resolve(hostname: string, rrtype?: "A" | "AAAA" | "ANY" | "CAA" | "CNAME" | "MX" | "NAPTR" | "NS" | "PTR" | "SOA" | "SRV" | "TXT" | string, options?:{ttl:boolean}): Promise<string[] | ARecord[] | AAAARecord[] | DNSRecord[] | { critical: number; iodef?: string; issue?: string }[] | { priority: number; exchange: string }[] | NAPTRRecord[] | CAARecord[] | SOARecord | SRVRecord[] | string[][]> {
        return this._fetch(`https://${this.getServers()[0]}/dns-query?name=${hostname}&type=${rrtype}&ct=application/dns-json`)
            .then(response => response.json())
            .then((data: Response) => {
                if (!data.Answer) throw DNSError.NODATA;
                switch (rrtype) {
                    default:
                    case 'A':
                    case 'AAAA':
                        if (options && options.ttl) return data.Answer.map(item=>({type: rrtype, address: item.data, ttl: item.TTL}));
                        // Fallthrough
                    case 'CNAME':
                    case 'NS':
                    case 'PTR':
                        return data.Answer.map(item=>item.data);
                    case 'ANY':
                        return data.Answer.map(item=>{
                            switch (item.type) {
                                case RecordType.A:
                                    return {type: 'A', address: item.data, ttl: item.TTL} as ARecord;
                                case RecordType.AAAA:
                                    return {type: 'AAAA', address: item.data, ttl: item.TTL} as AAAARecord;
                                case RecordType.CNAME:
                                    return {type: 'CNAME', value: item.data} as CNAMERecord;
                                case RecordType.NS:
                                    return {type: 'NS', value: item.data} as NSRecord;
                                case RecordType.PTR:
                                    return {type: 'PTR', value: item.data} as PTRRecord;
                                case RecordType.NAPTR:
                                    return parseNAPTR(item.data);
                                case RecordType.SOA:
                                    return parseSOA(item.data);
                                case RecordType.MX:
                                    return parseMX(item.data);
                                case RecordType.TXT:
                                    return {type: 'TXT', entries: item.data.split(' ')} as TXTRecord;
                                case RecordType.CAA:
                                    return parseCAA(item.data);
                            }
                        });
                    case 'MX':
                        return data.Answer.map(item=>parseMX(item.data));
                    case 'NAPTR':
                        return data.Answer.map(item=>parseNAPTR(item.data));
                    case 'SOA':
                        return data.Answer.map(item=>parseSOA(item.data))[0];
                    case 'SRV':
                        return data.Answer.map(item=>parseSRV(item.data));
                    case 'TXT':
                        return data.Answer.map(item=>item.data.split(' '));
                    case 'CAA':
                        return data.Answer.filter(item=>item.type===RecordType.CAA).map(item=>parseCAA(item.data));
                    case 'LOC':
                        return data.Answer.map(item=>parseLOC(item.data));
                    case 'SPF':
                        return data.Answer.map(item=>parseSPF(item.data));
                    case 'SVCB':
                        return data.Answer.map(item=>parseSVCB(item.data));
                    case 'URI':
                        return data.Answer.map(item=>parseURI(item.data));
                }
            }); // TODO catch CF specific errors and translate to internal error codes
    }
}
