import {ErrorCode} from "./constants";
import * as constants from "./constants.js";

export interface DNSRecord {
    type: string;
}

export interface ARecord extends DNSRecord {
    type: 'A';
    address: string;
    ttl: number;
}

export interface AAAARecord extends DNSRecord {
    type: 'AAAA';
    address: string;
    ttl: number;
}

export interface CNAMERecord extends DNSRecord {
    type: 'CNAME';
    value: string;
}

export interface NSRecord extends DNSRecord {
    type: 'NS';
    value: string;
}

export interface PTRRecord extends DNSRecord {
    type: 'PTR';
    value: string;
}

export interface TXTRecord extends DNSRecord {
    type: 'TXT';
    entries: string[];
}

export interface MXRecord extends DNSRecord {
    type: 'MX';
    entries: {
        priority: number,
        exchange: string
    }[];
}

export interface NAPTRRecord extends DNSRecord {
    type: 'NAPTR';
    flags: string;
    service: string;
    regexp: string;
    replacement: string;
    order: number;
    preference: number;
}

export interface SOARecord extends DNSRecord {
    type: 'SOA';
    nsname: string;
    hostmaster: string;
    serial: number;
    refresh: number;
    retry: number;
    expire: number;
    minttl: number;
}

export interface SRVRecord extends DNSRecord {
    type: 'SRV';
    priority: number;
    weight: number;
    port: number;
    name: string;
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
    resolve(hostname: string, rrtype: 'ANY', callback: (err?: DNSError, records?: DNSRecord[]) => void): void;
    resolve(hostname: string, rrtype: 'CAA', callback: (err?: DNSError, records?: {critical: number, iodef?: string, issue?: string}[]) => void): void;
    resolve(hostname: string, rrtype: 'MX', callback: (err?: DNSError, records?: {priority: number, exchange: string}[]) => void): void;
    resolve(hostname: string, rrtype: 'NAPTR', callback: (err?: DNSError, records?: NAPTRRecord[]) => void): void;
    resolve(hostname: string, rrtype: 'SOA', callback: (err?: DNSError, records?: SOARecord) => void): void;
    resolve(hostname: string, rrtype: 'SRV', callback: (err?: DNSError, records?: SRVRecord) => void): void;
    resolve(hostname: string, rrtype: 'TXT', callback: (err?: DNSError, records?: string[][]) => void): void;

    resolve4(hostname: string, callback: (err?: DNSError, address?: string[]) => void): void;
    resolve4(hostname: string, options: { ttl: true }, callback: (err?: DNSError, address?: ARecord[]) => void): void;
    resolve4(hostname: string, options: { ttl: false }, callback: (err?: DNSError, address?: string[]) => void): void;

    resolve6(hostname: string, callback: (err?: DNSError, address?: string[]) => void): void;
    resolve6(hostname: string, options: { ttl: true }, callback: (err?: DNSError, address?: AAAARecord[]) => void): void;
    resolve6(hostname: string, options: { ttl: false }, callback: (err?: DNSError, address?: string[]) => void): void;

    resolveAny(hostname: string, callback: (err?: DNSError, ret?: DNSRecord[]) => void): void;
    resolveCaa(hostname: string, callback: (err?: DNSError, records?: {critical: number, iodef?: string, issue?: string}[]) => void): void;
    resolveCname(hostname: string, callback: (err?: DNSError, addresses?: string[]) => void): void;
    resolveMx(hostname: string, callback: (err?: DNSError, addresses?: {priority: number, exchange: string}[]) => void): void;
    resolveNaptr(hostname: string, callback: (err?: DNSError, addresses?: NAPTRRecord[]) => void): void;
    resolveNs(hostname: string, callback: (err?: DNSError, addresses?: string[]) => void): void;
    resolvePtr(hostname: string, callback: (err?: DNSError, addresses?: string[]) => void): void;
    resolveSoa(hostname: string, callback: (err?: DNSError, address?: SOARecord) => void): void;
    resolveSrv(hostname: string, callback: (err?: DNSError, addresses?: SRVRecord) => void): void;
    resolveTxt(hostname: string, callback: (err?: DNSError, records?: string[][]) => void): void;
    reverse(hostname: string, callback: (err?: DNSError, hostnames?: string[]) => void): void;
}

export interface PromiseResolver {
    // constructor(options?: { timeout: number }): Resolver;
    cancel(): void;
    setLocalAddress(ipv4: string, ipv6: string): void;
    getServers(): string[];
    setServers(servers: string[]): void;

    resolve(hostname: string, rrtype?: "A"|"AAAA"|"CNAME"|"NS"|"PTR"): Promise<string[]>;
    resolve(hostname: string, rrtype: 'ANY'): Promise<DNSRecord[]>;
    resolve(hostname: string, rrtype: 'CAA'): Promise<{critical: number, iodef?: string, issue?: string}[]>;
    resolve(hostname: string, rrtype: 'MX'): Promise<{priority: number, exchange: string}[]>;
    resolve(hostname: string, rrtype: 'NAPTR'): Promise<NAPTRRecord[]>;
    resolve(hostname: string, rrtype: 'SOA'): Promise<SOARecord>;
    resolve(hostname: string, rrtype: 'SRV'): Promise<SRVRecord>;
    resolve(hostname: string, rrtype: 'TXT'): Promise<string[][]>;

    resolve4(hostname: string, options: { ttl: true }): Promise<ARecord[]>;
    resolve4(hostname: string, options?: { ttl: false }): Promise<string[]>;

    resolve6(hostname: string, options: { ttl: true }): Promise<AAAARecord[]>;
    resolve6(hostname: string, options?: { ttl: false }): Promise<string[]>;

    resolveAny(hostname: string): Promise<DNSRecord[]>;
    resolveCaa(hostname: string): Promise<{critical: number, iodef?: string, issue?: string}[]>;
    resolveCname(hostname: string): Promise<string[]>;
    resolveMx(hostname: string): Promise<{priority: number, exchange: string}[]>;
    resolveNaptr(hostname: string): Promise<NAPTRRecord[]>;
    resolveNs(hostname: string): Promise<string[]>;
    resolvePtr(hostname: string): Promise<string[]>;
    resolveSoa(hostname: string): Promise<SOARecord>;
    resolveSrv(hostname: string): Promise<SRVRecord>;
    resolveTxt(hostname: string): Promise<string[][]>;

    reverse(hostname: string): Promise<string[]>;
}
