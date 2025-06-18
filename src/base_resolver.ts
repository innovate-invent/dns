import {
    AAAARecord,
    AnyDNSRecord,
    ARecord,
    DNSError,
    NAPTRRecord,
    PromiseResolver,
    ResolveOptions,
    SOARecord,
    SRVRecord
} from "./dns.js";
import {RecordType} from "./constants.js";
import {DOMAINNAME, RDATA} from "./rfc_rdata.js";

export type BaseResolverOptions = {
    timeout?: number,  // Timeout in milliseconds for a request
    tries?: number,  // Number of retries for failed requests
};

// eslint-disable-next-line @typescript-eslint/no-empty-object-type, @typescript-eslint/no-unsafe-declaration-merging
export interface BaseResolver extends PromiseResolver {
    // Allows partial implementation of PromiseResolver in abstract class using declaration merging
}

// eslint-disable-next-line @typescript-eslint/no-unsafe-declaration-merging
export abstract class BaseResolver implements PromiseResolver {
    protected readonly _timeout: number = -1;
    protected readonly _tries: number = 4;
    protected abstract servers: string[];
    protected readonly dsOverrides = new Map<string, RDATA[RecordType.DS][]>();

    constructor(options?: BaseResolverOptions) {
        if (!options) return;
        if (options.timeout !== undefined)
            if (!Number.isInteger(options.timeout)) throw new TypeError("timeout must be an integer");
            else if (options.timeout < -1) throw new RangeError("timeout must be >= -1");
            else this._timeout = options.timeout;

        if (options.tries !== undefined)
            if (!Number.isInteger(options.tries)) throw new TypeError("tries must be an integer");
            else if (options.tries < 1) throw new RangeError("tries must be >= 1");
            else this._tries = options.tries;
    }

    abstract cancel(): void;

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    setLocalAddress(ipv4: string, ipv6: string): void {
        // no-op
    }

    getServers(): string[] {
        return this.servers;
    }

    setServers(servers: string[]): void {
        if (servers.length === 0) throw new RangeError("At least one server is required");
        this.servers = servers;
    }

    getDSOverride(name: DOMAINNAME): RDATA[RecordType.DS][] {
        let key = name.join('.').toLowerCase();
        if (key.at(-1) !== '.') key += '.';
        return this.dsOverrides.get(key);
    }

    setDSOverride(name: DOMAINNAME, ds: RDATA[RecordType.DS][]) {
        let key = name.join('.').toLowerCase();
        if (key.at(-1) !== '.') key += '.';
        if (ds) this.dsOverrides.set(key, ds);
        else this.dsOverrides.delete(key);
    }
    
    abstract resolve(hostname: string, rrtype?: (keyof typeof RecordType) | 'ANY', options?: ResolveOptions): Promise<any>;
    abstract resolve(questions: { hostname: string, rrtype: (keyof typeof RecordType) }[], options?: ResolveOptions & {
        raw: true
    }): Promise<any[]>; 

    resolve4(hostname: string, options: { ttl: true }): Promise<ARecord[]>;
    resolve4(hostname: string, options?: { ttl: false }): Promise<string[]>;
    resolve4(hostname: string, options?: { ttl: boolean }): Promise<string[] | ARecord[]> {
        return this.resolve(hostname, 'A', options);
    }

    resolve6(hostname: string, options: { ttl: true }): Promise<AAAARecord[]>;
    resolve6(hostname: string, options?: { ttl: false }): Promise<string[]>;
    resolve6(hostname: string, options?: { ttl: boolean }): Promise<string[] | AAAARecord[]> {
        return this.resolve(hostname, 'AAAA', options);
    }

    resolveAny(hostname: string): Promise<AnyDNSRecord[]> {
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

    resolveSrv(hostname: string): Promise<SRVRecord[]> {
        return this.resolve(hostname, 'SRV');
    }

    resolveTxt(hostname: string): Promise<string[][]> {
        return this.resolve(hostname, 'TXT');
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    reverse(hostname: string): Promise<string[]> {
        throw DNSError.NOTIMP;
    }
}
