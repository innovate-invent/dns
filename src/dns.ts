import * as constants from "./constants.js";
import {ErrorCode, RecordType} from "./constants.js";

export type DNSRecord = {}

export interface AnyDNSRecord {
    type: string;
}

export interface ARecord extends DNSRecord {
    address: string;
    ttl: number;
}

export interface AnyARecord extends ARecord {
    type: 'A';
}

export interface AAAARecord extends DNSRecord {
    address: string;
    ttl: number;
}

export interface AnyAAAARecord extends AAAARecord {
    type: 'AAAA';
}

export interface CNAMERecord extends DNSRecord {
    value: string;
}

export interface AnyCNAMERecord extends CNAMERecord {
    type: 'CNAME';
}

export interface CAARecord extends DNSRecord {
    critical: number;
    iodef?: string;
    issue?: string;
}

export interface AnyCAARecord extends CAARecord {
    type: 'CAA';
}

export interface NSRecord extends DNSRecord {
    value: string;
}

export interface AnyNSRecord extends NSRecord {
    type: 'NS';
}

export interface PTRRecord extends DNSRecord {
    value: string;
}

export interface AnyPTRRecord extends PTRRecord {
    type: 'PTR';
}

export interface TXTRecord extends DNSRecord {
    entries: string[];
}

export interface AnyTXTRecord extends TXTRecord {
    type: 'TXT';
}

export interface MXRecord extends DNSRecord {
    priority: number;
    exchange: string;
}

export interface AnyMXRecord extends MXRecord {
    type: 'MX';
}

export interface NAPTRRecord extends DNSRecord {
    order: number;
    preference: number;
    flags: string;
    service: string;
    regexp: string;
    replacement: string;
}

export interface AnyNAPTRRecord extends NAPTRRecord {
    type: 'NAPTR';
}

export interface SOARecord extends DNSRecord {
    nsname: string;
    hostmaster: string;
    serial: number;
    refresh: number;
    retry: number;
    expire: number;
    minttl: number;
}

export interface AnySOARecord extends SOARecord {
    type: 'SOA';
}

export interface SRVRecord extends DNSRecord {
    priority: number;
    weight: number;
    port: number;
    name: string;
}

export interface AnySRVRecord extends SRVRecord {
    type: 'SRV';
}

export class DNSError extends Error {
    code: ErrorCode;
    constructor(message: string, code: ErrorCode) {
        super(message);
        this.code = code;
    }

    static readonly NODATA = new DNSError('DNS server returned answer with no data', constants.NODATA);
    static readonly FORMERR = new DNSError('DNS server claims query was misformatted', constants.FORMERR);
    static readonly SERVFAIL = new DNSError('DNS server returned general failure', constants.SERVFAIL);
    static readonly NOTFOUND = new DNSError('Domain name not found', constants.NOTFOUND);
    static readonly NOTIMP = new DNSError('DNS server does not implement requested operation', constants.NOTIMP);
    static readonly REFUSED = new DNSError('DNS server refused query', constants.REFUSED);
    static readonly BADQUERY = new DNSError('Misformatted DNS query', constants.BADQUERY);
    static readonly BADNAME = new DNSError('Misformatted host name', constants.BADNAME);
    static readonly BADFAMILY = new DNSError('Unsupported address family', constants.BADFAMILY);
    static readonly BADRESP = new DNSError('Misformatted DNS reply', constants.BADRESP);
    static readonly CONNREFUSED = new DNSError('Could not contact DNS servers', constants.CONNREFUSED);
    static readonly TIMEOUT = new DNSError('Timeout while contacting DNS servers', constants.TIMEOUT);
    static readonly EOF = new DNSError('End of file', constants.EOF);
    static readonly FILE = new DNSError('Error reading file', constants.FILE);
    static readonly NOMEM = new DNSError('Out of memory', constants.NOMEM);
    static readonly DESTRUCTION = new DNSError('Channel is being destroyed', constants.DESTRUCTION);
    static readonly BADSTR = new DNSError('Misformatted string', constants.BADSTR);
    static readonly BADFLAGS = new DNSError('Illegal flags specified', constants.BADFLAGS);
    static readonly NONAME = new DNSError('Given host name is not numeric', constants.NONAME);
    static readonly BADHINTS = new DNSError('Illegal hints flags specified', constants.BADHINTS);
    static readonly NOTINITIALIZED = new DNSError('c-ares library initialization not yet performed', constants.NOTINITIALIZED);
    static readonly LOADIPHLPAPI = new DNSError('Error loading iphlpapi.dll', constants.LOADIPHLPAPI);
    static readonly ADDRGETNETWORKPARAMS = new DNSError('Could not find GetNetworkParams function', constants.ADDRGETNETWORKPARAMS);
    static readonly CANCELLED = new DNSError('DNS query cancelled', constants.CANCELLED);
}

export type LookupCallback = (err?: DNSError, address?: string, family?: number) => void;
export type LookupCallbackAll = (err?: DNSError, addresses?: { address: string, family: number }[]) => void;

export interface Resolver {
    // constructor(options?: { timeout: number });
    cancel(): void;
    setLocalAddress(ipv4: string, ipv6: string): void;
    getServers(): string[];
    setServers(servers: string[]): void;

    resolve(hostname: string, callback: (err?: DNSError, records?: string[]) => void): void;
    resolve(hostname: string, rrtype: "A"|"AAAA"|"CNAME"|"NS"|"PTR", callback: (err?: DNSError, records?: string[]) => void): void;
    resolve(hostname: string, rrtype: 'ANY', callback: (err?: DNSError, records?: AnyDNSRecord[]) => void): void;
    resolve(hostname: string, rrtype: 'CAA', callback: (err?: DNSError, records?: CAARecord[]) => void): void;
    resolve(hostname: string, rrtype: 'MX', callback: (err?: DNSError, records?: MXRecord[]) => void): void;
    resolve(hostname: string, rrtype: 'NAPTR', callback: (err?: DNSError, records?: NAPTRRecord[]) => void): void;
    resolve(hostname: string, rrtype: 'SOA', callback: (err?: DNSError, records?: SOARecord) => void): void;
    resolve(hostname: string, rrtype: 'SRV', callback: (err?: DNSError, records?: SRVRecord[]) => void): void;
    resolve(hostname: string, rrtype: 'TXT', callback: (err?: DNSError, records?: string[][]) => void): void;

    resolve4(hostname: string, callback: (err?: DNSError, address?: string[]) => void): void;
    resolve4(hostname: string, options: { ttl: true }, callback: (err?: DNSError, address?: ARecord[]) => void): void;
    resolve4(hostname: string, options: { ttl: false }, callback: (err?: DNSError, address?: string[]) => void): void;

    resolve6(hostname: string, callback: (err?: DNSError, address?: string[]) => void): void;
    resolve6(hostname: string, options: { ttl: true }, callback: (err?: DNSError, address?: AAAARecord[]) => void): void;
    resolve6(hostname: string, options: { ttl: false }, callback: (err?: DNSError, address?: string[]) => void): void;

    resolveAny(hostname: string, callback: (err?: DNSError, ret?: AnyDNSRecord[]) => void): void;
    resolveCaa(hostname: string, callback: (err?: DNSError, records?: {critical: number, iodef?: string, issue?: string}[]) => void): void;
    resolveCname(hostname: string, callback: (err?: DNSError, addresses?: string[]) => void): void;
    resolveMx(hostname: string, callback: (err?: DNSError, addresses?: {priority: number, exchange: string}[]) => void): void;
    resolveNaptr(hostname: string, callback: (err?: DNSError, addresses?: NAPTRRecord[]) => void): void;
    resolveNs(hostname: string, callback: (err?: DNSError, addresses?: string[]) => void): void;
    resolvePtr(hostname: string, callback: (err?: DNSError, addresses?: string[]) => void): void;
    resolveSoa(hostname: string, callback: (err?: DNSError, address?: SOARecord) => void): void;
    resolveSrv(hostname: string, callback: (err?: DNSError, addresses?: SRVRecord[]) => void): void;
    resolveTxt(hostname: string, callback: (err?: DNSError, records?: string[][]) => void): void;
    reverse(hostname: string, callback: (err?: DNSError, hostnames?: string[]) => void): void;
}

export type ResolveOptions = {ttl?:boolean, raw?: boolean, dnssec?: boolean};

export interface PromiseResolver {
    // constructor(options?: { timeout: number }): Resolver;
    cancel(): void;
    setLocalAddress(ipv4: string, ipv6: string): void;
    getServers(): string[];
    setServers(servers: string[]): void;

    resolve(hostname: string, rrtype: "ANY", options?: {raw: false}): Promise<AnyDNSRecord[]>;
    resolve(hostname: string, rrtype: "CAA", options?: {raw: false}): Promise<CAARecord[]>;
    resolve(hostname: string, rrtype: "MX", options?: {raw: false}): Promise<MXRecord[]>;
    resolve(hostname: string, rrtype: "NAPTR", options?: {raw: false}): Promise<NAPTRRecord[]>;
    resolve(hostname: string, rrtype: "SOA", options?: {raw: false}): Promise<SOARecord>;
    resolve(hostname: string, rrtype: "SRV", options?: {raw: false}): Promise<SRVRecord[]>;
    resolve(hostname: string, rrtype: "TXT", options?: {raw: false}): Promise<string[][]>;
    resolve(hostname: string, rrtype?: "A"|"AAAA"|"CNAME"|"NS"|"PTR", options?: {raw: false}): Promise<string[]>;
    resolve(hostname: string, rrtype: keyof typeof RecordType, options: {raw: true}): Promise<any>;
    resolve(hostname: string, rrtype: "A", options: {ttl:true, raw: false}): Promise<ARecord[]>;
    resolve(hostname: string, rrtype: "AAAA", options: {ttl:true, raw: false}): Promise<AAAARecord[]>;

    resolve4(hostname: string, options: { ttl: true }): Promise<ARecord[]>;
    resolve4(hostname: string, options?: { ttl: false }): Promise<string[]>;

    resolve6(hostname: string, options: { ttl: true }): Promise<AAAARecord[]>;
    resolve6(hostname: string, options?: { ttl: false }): Promise<string[]>;

    resolveAny(hostname: string): Promise<AnyDNSRecord[]>;
    resolveCaa(hostname: string): Promise<{critical: number, iodef?: string, issue?: string}[]>;
    resolveCname(hostname: string): Promise<string[]>;
    resolveMx(hostname: string): Promise<{priority: number, exchange: string}[]>;
    resolveNaptr(hostname: string): Promise<NAPTRRecord[]>;
    resolveNs(hostname: string): Promise<string[]>;
    resolvePtr(hostname: string): Promise<string[]>;
    resolveSoa(hostname: string): Promise<SOARecord>;
    resolveSrv(hostname: string): Promise<SRVRecord[]>;
    resolveTxt(hostname: string): Promise<string[][]>;

    reverse(hostname: string): Promise<string[]>;

    // Not part of spec, but provided here to be hooked by CallbackResolver
    lookup(hostname: string): Promise<{ address: string, family: number }>;
    lookup(hostname: string, options: 4 | 6 | { family: 4 | 6 | 0, hints?: number, all?: boolean, verbatim?: boolean }): Promise<{ address: string, family: number } | { address: string, family: number }[]>;
    lookupService(address: string, port: number): Promise<{hostname: string, service: string}>
}
