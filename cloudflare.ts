import * as dns from './dns'
import {AAAARecord, ARecord, CNAMERecord, DNSError, DNSRecord, NAPTRRecord, SOARecord, SRVRecord} from './dns'
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

export default class Resolver implements dns.promises.Resolver {
    _timeout: number = -1;

    constructor(options?: { timeout: number }) {
        if (options) this._timeout = options.timeout;
    }

    _pending: Set<AbortController> = new Set();

    cancel(): void {
        for (const controller of this._pending) controller.abort();
        this._pending.clear();
    }

    getServers(): string[] {
        return ['cloudflare-dns.com'];
    }

    resolve(hostname: string): Promise<string[]>;
    resolve(hostname: string, rrtype: "A"): Promise<string[]>;
    resolve(hostname: string, rrtype: "AAAA"): Promise<string[]>;
    resolve(hostname: string, rrtype: "ANY"): Promise<DNSRecord[]>;
    resolve(hostname: string, rrtype: "CAA"): Promise<{ critical: number; iodef?: string; issue?: string }[]>;
    resolve(hostname: string, rrtype: "CNAME"): Promise<string[]>;
    resolve(hostname: string, rrtype: "MX"): Promise<{ priority: number; exchange: string }[]>;
    resolve(hostname: string, rrtype: "NAPTR"): Promise<NAPTRRecord[]>;
    resolve(hostname: string, rrtype: "NS"): Promise<string[]>;
    resolve(hostname: string, rrtype: "PTR"): Promise<string[]>;
    resolve(hostname: string, rrtype: "SOA"): Promise<SOARecord>;
    resolve(hostname: string, rrtype: "SRV"): Promise<SRVRecord>;
    resolve(hostname: string, rrtype: "TXT"): Promise<string[][]>;
    resolve(hostname: string, rrtype?: "A" | "AAAA" | "ANY" | "CAA" | "CNAME" | "MX" | "NAPTR" | "NS" | "PTR" | "SOA" | "SRV" | "TXT"): Promise<string[] | DNSRecord[] | { critical: number; iodef?: string; issue?: string }[] | { priority: number; exchange: string }[] | NAPTRRecord[] | SOARecord | SRVRecord | string[][]> {
        let controller;
        return fetchWithTimeout(`https://cloudflare-dns.com/dns-query?name=${hostname}&type=${rrtype}&ct=application/dns-json`, {
            timeout: this._timeout,
            abortCB: c => {
                this._pending.add(c);
                controller = c
            }
        })
            .then(response => response.json())
            .then((data: Response) => {
                this._pending.delete(controller);
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
                                    return <ARecord>{address: item.data, ttl: item.TTL};
                                case RecordType.AAAA:
                                    return <AAAARecord>{address: item.data, ttl: item.TTL};
                                case RecordType.CNAME:
                                    return <CNAMERecord>{value: item.data};
                                case RecordType.NAPTR:
                                    return <NAPTRRecord>{}; // TODO
                                case RecordType.SOA:
                                    return <SOARecord>{} //TODO
                            }
                        });
                    case 'MX':
                    case 'NAPTR':
                    case 'SOA':
                    case 'SRV':
                    case 'TXT':
                        throw new Error('Not implemented'); // TODO parse response into record types
                }
            }).catch(e => {
                this._pending.delete(controller);
                if (e.name === 'AbortError') throw new DNSError('request was cancelled', CANCELLED);
                throw(e);
            });
    }

    resolve4(hostname: string): Promise<string[]>;
    resolve4(hostname: string, options: { ttl: true }): Promise<ARecord[]>;
    resolve4(hostname: string, options: { ttl: false }): Promise<string[]>;
    resolve4(hostname: string, options?: { ttl: true } | { ttl: false }): Promise<string[] | ARecord[]> {
        return this.resolve(hostname, 'A');
    }

    resolve6(hostname: string): Promise<string[]>;
    resolve6(hostname: string, options: { ttl: true }): Promise<AAAARecord[]>;
    resolve6(hostname: string, options: { ttl: false }): Promise<string[]>;
    resolve6(hostname: string, options?: { ttl: true } | { ttl: false }): Promise<string[] | AAAARecord[]> {
        return this.resolve(hostname, 'AAAA');
    }

    resolveAny(hostname: string): Promise<DNSRecord[]> {
        return this.resolve(hostname, 'ANY');
    }

    resolveCaa(hostname: string): Promise<{ critical: number; iodef?: string; issue?: string }[]> {
        return this.resolve(hostname, 'CAA');
    }

    resolveCname(hostname: string): Promise<string[]> {
        return this.resolve(hostname, 'CNAME');
    }

    resolveMx(hostname: string): Promise<{ priority: number; exchange: string }[]> {
        return this.resolve(hostname, 'MX');
    }

    resolveNaptr(hostname: string): Promise<NAPTRRecord[]> {
        return this.resolve(hostname, 'NAPTR');
    }

    resolveNs(hostname: string): Promise<string[]> {
        return this.resolve(hostname, 'NS');
    }

    resolvePtr(hostname: string): Promise<string[]> {
        return this.resolve(hostname, 'PTR');
    }

    resolveSoa(hostname: string): Promise<SOARecord> {
        return this.resolve(hostname, 'SOA');
    }

    resolveSrv(hostname: string): Promise<SRVRecord> {
        return this.resolve(hostname, 'SRV');
    }

    resolveTxt(hostname: string): Promise<string[][]> {
        return this.resolve(hostname, 'TXT');
    }

    reverse(hostname: string): Promise<string[]> {
        throw new dns.DNSError("not implemented", NOTIMP);
    }

    setLocalAddress(ipv4: string, ipv6: string): void {
    }

    setServers(servers: string[]): void {
    }

    lookup(hostname: string, options?: 4 | 6 | { family: 4 | 6 | 0, hints: number, all: boolean, verbatim: boolean }): Promise<{address: string, family: number} | { address: string, family: number }[]> {
        let rrtype: "A" | "AAAA" = 'A';
        if (options === 6 || (typeof options === 'object' && options.family === 6)) rrtype = 'AAAA';
        // @ts-ignore
        return this.resolve(hostname, rrtype).then(records => {
            if (typeof options === 'object' && options.family === 0) {
                return this.resolve(hostname, 'AAAA').then(records6 => {
                    return (<string[]>records.concat(<string[]>records6)).map((record: string) => {
                        return {address: record, family: rrtype === 'A' ? 4 : 6}
                    });
                });
            } else if (typeof options === 'object' && options.all) {
                return (<string[]>records).map((record: string) => {
                    return {address: record, family: rrtype === 'A' ? 4 : 6}
                });
            } else {
                return records[0], rrtype === 'A' ? 4 : 6;
            }
        });
    }

    lookupService(address: string, port: number): Promise<{hostname: string, service: string}> {
        throw new DNSError("not implemented", NOTIMP);
    }
}
