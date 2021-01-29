import { BaseResolver } from './base_resolver'
import {AAAARecord, ARecord, CNAMERecord, DNSRecord, NAPTRRecord, SOARecord, SRVRecord} from './dns'
import {CANCELLED, NOTIMP, RecordType} from "./constants";

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
}

export default class Resolver extends BaseResolver {
    getServers(): string[] {
        return ['cloudflare-dns.com'];
    }

    resolve(hostname: string, rrtype?: "A"|"AAAA"|"CNAME"|"NS"|"PTR"): Promise<string[]>;
    resolve(hostname: string, rrtype: "ANY"): Promise<DNSRecord[]>;
    resolve(hostname: string, rrtype: "CAA"): Promise<{ critical: number; iodef?: string; issue?: string }[]>;
    resolve(hostname: string, rrtype: "MX"): Promise<{ priority: number; exchange: string }[]>;
    resolve(hostname: string, rrtype: "NAPTR"): Promise<NAPTRRecord[]>;
    resolve(hostname: string, rrtype: "SOA"): Promise<SOARecord>;
    resolve(hostname: string, rrtype: "SRV"): Promise<SRVRecord>;
    resolve(hostname: string, rrtype: "TXT"): Promise<string[][]>;
    resolve(hostname: string, rrtype?: "A" | "AAAA" | "ANY" | "CAA" | "CNAME" | "MX" | "NAPTR" | "NS" | "PTR" | "SOA" | "SRV" | "TXT"): Promise<string[] | DNSRecord[] | { critical: number; iodef?: string; issue?: string }[] | { priority: number; exchange: string }[] | NAPTRRecord[] | SOARecord | SRVRecord | string[][]> {
        return this._fetch(`https://cloudflare-dns.com/dns-query?name=${hostname}&type=${rrtype}&ct=application/dns-json`)
            .then(response => response.json())
            .then((data: Response) => {
                switch (rrtype) {
                    default:
                    case 'A':
                    case 'AAAA':
                    case 'CNAME':
                    case 'NS':
                    case 'PTR':
                        return data.Answer.map(item => item.data);
                        break;
                    case 'ANY':
                        return data.Answer.map(item=>{
                            switch (item.type) {
                                case RecordType.A:
                                    return {address: item.data, ttl: item.TTL} as ARecord;
                                case RecordType.AAAA:
                                    return {address: item.data, ttl: item.TTL} as AAAARecord;
                                case RecordType.CNAME:
                                    return {value: item.data} as CNAMERecord;
                                case RecordType.NAPTR:
                                    return {} as NAPTRRecord; // TODO
                                case RecordType.SOA:
                                    return {} as SOARecord; // TODO
                            }
                        });
                    case 'MX':
                    case 'NAPTR':
                    case 'SOA':
                    case 'SRV':
                    case 'TXT':
                        throw new Error('Not implemented'); // TODO parse response into record types
                }
            });
    }
}
