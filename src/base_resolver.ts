import {
    AAAARecord,
    ARecord,
    CNAMERecord,
    DNSError,
    DNSRecord,
    NAPTRRecord,
    PromiseResolver,
    SOARecord,
    SRVRecord
} from "./dns.js";
import {CANCELLED, NOTIMP, RecordType} from "./constants.js";
import * as dns from "./dns.js";

// tslint:disable-next-line no-empty-interface
export interface BaseResolver extends PromiseResolver {} // Allows partial implementation of PromiseResolver in abstract class using declaration merging
export abstract class BaseResolver implements PromiseResolver {
    private readonly _timeout: number = -1;
    protected servers: string[];

    constructor(options?: { timeout: number }) {
        if (options) this._timeout = options.timeout;
    }

    _pending: Set<AbortController> = new Set();

    cancel(): void {
        for (const controller of this._pending) controller.abort();
        this._pending.clear();
    }

    protected async _fetch(resource: string, options?: object): Promise<Response> {
        const controller = new AbortController();
        let id;
        this._pending.add(controller);
        if (this._timeout !== -1) id = setTimeout(() => controller.abort(), this._timeout);

        try {
            return await fetch(resource, {
                ...options,
                signal: controller.signal
            });
        } catch (e) {
            if (e.name === 'AbortError') throw new DNSError('request was cancelled', CANCELLED);
            throw(e);
        } finally {
            this._pending.delete(controller);
            if (id) clearTimeout(id);
        }
    }

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

    abstract resolve(hostname: string, rrtype?: "A"|"AAAA"|"CNAME"|"NS"|"PTR", options?:{ttl:boolean}): Promise<string[]>;
    abstract resolve(hostname: string, rrtype: "ANY", options?:{ttl:boolean}): Promise<DNSRecord[]>;
    abstract resolve(hostname: string, rrtype: "CAA", options?:{ttl:boolean}): Promise<{ critical: number; iodef?: string; issue?: string }[]>;
    abstract resolve(hostname: string, rrtype: "MX", options?:{ttl:boolean}): Promise<{ priority: number; exchange: string }[]>;
    abstract resolve(hostname: string, rrtype: "NAPTR", options?:{ttl:boolean}): Promise<NAPTRRecord[]>;
    abstract resolve(hostname: string, rrtype: "SOA", options?:{ttl:boolean}): Promise<SOARecord>;
    abstract resolve(hostname: string, rrtype: "SRV", options?:{ttl:boolean}): Promise<SRVRecord[]>;
    abstract resolve(hostname: string, rrtype: "TXT", options?:{ttl:boolean}): Promise<string[][]>;
    abstract resolve(hostname: string, rrtype?: "A" | "AAAA" | "ANY" | "CAA" | "CNAME" | "MX" | "NAPTR" | "NS" | "PTR" | "SOA" | "SRV" | "TXT", options?:{ttl:boolean}): Promise<string[] | DNSRecord[] | { critical: number; iodef?: string; issue?: string }[] | { priority: number; exchange: string }[] | NAPTRRecord[] | SOARecord | SRVRecord[] | string[][]>;

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

    resolveSrv(hostname: string): Promise<SRVRecord[]> {
        return this.resolve(hostname, 'SRV');
    }

    resolveTxt(hostname: string): Promise<string[][]> {
        return this.resolve(hostname, 'TXT');
    }

    reverse(hostname: string): Promise<string[]> {
        throw DNSError.NOTIMP;
    }
}
