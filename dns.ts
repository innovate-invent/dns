import {ErrorCode} from "./constants";

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
}

export interface LookupCallback {
    (err: DNSError | undefined, address: string, family: number): void;
}

export interface LookupCallbackAll {
    (err: DNSError | undefined, addresses: { address: string, family: number }[]): void;
}

export interface Resolver {
    constructor(options?: { timeout: number }): Resolver;
    cancel(): void;
    setLocalAddress(ipv4: string, ipv6: string): void;
    getServers(): string[];
    setServers(servers: string[]): void;

    resolve(hostname: string, callback: (err?: DNSError, records?: string[]) => void): void;
    resolve(hostname: string, rrtype: 'A', callback: (err?: DNSError, records?: string[]) => void): void;
    resolve(hostname: string, rrtype: 'AAAA', callback: (err?: DNSError, records?: string[]) => void): void;
    resolve(hostname: string, rrtype: 'ANY', callback: (err?: DNSError, records?: DNSRecord[]) => void): void;
    resolve(hostname: string, rrtype: 'CAA', callback: (err?: DNSError, records?: {critical: number, iodef?: string, issue?: string}[]) => void): void;
    resolve(hostname: string, rrtype: 'CNAME', callback: (err?: DNSError, records?: string[]) => void): void;
    resolve(hostname: string, rrtype: 'MX', callback: (err?: DNSError, records?: {priority: number, exchange: string}[]) => void): void;
    resolve(hostname: string, rrtype: 'NAPTR', callback: (err?: DNSError, records?: NAPTRRecord[]) => void): void;
    resolve(hostname: string, rrtype: 'NS', callback: (err?: DNSError, records?: string[]) => void): void;
    resolve(hostname: string, rrtype: 'PTR', callback: (err?: DNSError, records?: string[]) => void): void;
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

export namespace promises {
    export interface Resolver { //TODO abstract class, move in most of CFResolver
        constructor(options?: { timeout: number }): Resolver;
        cancel(): void;
        setLocalAddress(ipv4: string, ipv6: string): void;
        getServers(): string[];
        setServers(servers: string[]): void;

        resolve(hostname: string): Promise<string[]>;
        resolve(hostname: string, rrtype: 'A'): Promise<string[]>;
        resolve(hostname: string, rrtype: 'AAAA'): Promise<string[]>;
        resolve(hostname: string, rrtype: 'ANY'): Promise<DNSRecord[]>;
        resolve(hostname: string, rrtype: 'CAA'): Promise<{critical: number, iodef?: string, issue?: string}[]>;
        resolve(hostname: string, rrtype: 'CNAME'): Promise<string[]>;
        resolve(hostname: string, rrtype: 'MX'): Promise<{priority: number, exchange: string}[]>;
        resolve(hostname: string, rrtype: 'NAPTR'): Promise<NAPTRRecord[]>;
        resolve(hostname: string, rrtype: 'NS'): Promise<string[]>;
        resolve(hostname: string, rrtype: 'PTR'): Promise<string[]>;
        resolve(hostname: string, rrtype: 'SOA'): Promise<SOARecord>;
        resolve(hostname: string, rrtype: 'SRV'): Promise<SRVRecord>;
        resolve(hostname: string, rrtype: 'TXT'): Promise<string[][]>;

        resolve4(hostname: string): Promise<string[]>;
        resolve4(hostname: string, options: { ttl: true }): Promise<ARecord[]>;
        resolve4(hostname: string, options: { ttl: false }): Promise<string[]>;

        resolve6(hostname: string): Promise<string[]>;
        resolve6(hostname: string, options: { ttl: true }): Promise<AAAARecord[]>;
        resolve6(hostname: string, options: { ttl: false }): Promise<string[]>;

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
}
