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

export type BaseResolverOptions = { timeout?: number, tries?: number };
// tslint:disable-next-line no-empty-interface
export interface BaseResolver extends PromiseResolver {} // Allows partial implementation of PromiseResolver in abstract class using declaration merging
export abstract class BaseResolver implements PromiseResolver {
    private readonly _timeout: number = -1;
    private readonly _tries: number = 4;
    protected servers: string[];

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

    _pending: Set<AbortController> = new Set();

    cancel(): void {
        for (const controller of this._pending) controller.abort();
        this._pending.clear();
    }

    /**
     * Fetch with abort, timeout, and retry
     * @param resource URL of resource to fetch
     * @param options RequestInit options to forward to fetch
     * @protected
     */
    protected async _fetch(resource: string, options?: RequestInit): Promise<Response> {
        const controller = new AbortController();
        let id;
        this._pending.add(controller);

        try {
            for (let _try = this._tries; _try > 0; --_try) {
                let timeout = false;
                if (this._timeout !== -1) id = setTimeout(() => {timeout = true; controller.abort();}, this._timeout);
                try {
                    return await fetch(resource, {
                        ...options,
                        signal: controller.signal
                    });
                } catch (e) {
                    if (e.name === 'AbortError') {
                        if (timeout) throw DNSError.TIMEOUT;
                        throw DNSError.CANCELLED;
                    }
                    if (_try > 0) continue;
                    // TODO translate e to DNSErrors
                    switch (e.name) {
                        case '':

                    }
                    throw e;
                } finally {
                    if (id) clearTimeout(id);
                }
            }
        } finally {
            this._pending.delete(controller);
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

    abstract resolve(hostname: string, rrtype?: (keyof typeof RecordType) | 'ANY', options?: ResolveOptions): Promise<any>;

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

    reverse(hostname: string): Promise<string[]> {
        throw DNSError.NOTIMP;
    }
}
