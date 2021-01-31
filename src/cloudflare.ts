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
    parseCAA,
    parseMX,
    parseNAPTR,
    parseSOA,
    parseSRV,
    PTRRecord,
    SOARecord,
    SRVRecord,
    TXTRecord,
} from './dns.js'
import {RecordType} from "./constants.js";

interface Response {
    Status: number; // The Response Code of the DNS Query. These are defined here: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
    TC: boolean; // If true, it means the truncated bit was set. This happens when the DNS answer is larger than a single UDP or TCP packet. TC will almost always be false with Cloudflare DNS over HTTPS because Cloudflare supports the maximum response size.
    RD: boolean; // If true, it means the Recursive Desired bit was set. This is always set to true for Cloudflare DNS over HTTPS.
    RA: boolean; // If true, it means the Recursion Available bit was set. This is always set to true for Cloudflare DNS over HTTPS.
    AD: boolean; // If true, it means that every record in the answer was verified with DNSSEC.
    CD: boolean; // If true, the client asked to disable DNSSEC validation. In this case, Cloudflare will still fetch the DNSSEC-related records, but it will not attempt to validate the records.
    Question: [{
        name: string; // The record name requested.
        type: RecordType; // The type of DNS record requested. These are defined here: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
    }];
    Answer: [{
        name: string; // The record owner.
        type: RecordType; // The type of DNS record. These are defined here: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
        TTL: number; // The number of seconds the answer can be stored in cache before it is considered stale.
        data: string; // The value of the DNS record for the given name and type. The data will be in text for standardized record types and in hex for unknown types.
    }];
    Authority: [{
        name: string; // The record owner.
        type: RecordType; // The type of DNS record. These are defined here: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
        TTL: number; // The number of seconds the answer can be stored in cache before it is considered stale.
        data: string; // The value of the DNS record for the given name and type. The data will be in text for standardized record types and in hex for unknown types.
    }];
}

export default class Resolver extends BaseResolver {
    protected servers: string[] = ['cloudflare-dns.com'];

    resolve(hostname: string, rrtype?: "A"|"AAAA"|"CNAME"|"NS"|"PTR"): Promise<string[]>;
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
                        return data.Answer.map(item => item.data);
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
                        return data.Answer.map(item=>item.data);// TODO parseNAPTR(item.data));
                    case 'SOA':
                        return data.Answer.map(item=>parseSOA(item.data))[0];
                    case 'SRV':
                        return data.Answer.map(item=>parseSRV(item.data));
                    case 'TXT':
                        return data.Answer.map(item=>item.data.split(' '));
                    case 'CAA':
                        return data.Answer.filter(item=>item.type===RecordType.CAA).map(item=>item.data); // TODO parseCAA(item.data));
                }
            }); // TODO catch CF specific errors and translate to internal error codes
    }
}
