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
} from "./dns";
import {CANCELLED, NOTIMP, RecordType} from "./constants";
import * as dns from "./dns";

// tslint:disable-next-line no-empty-interface
export interface BaseResolver extends PromiseResolver {}
export abstract class BaseResolver implements PromiseResolver {
    _timeout: number = -1;

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

    abstract getServers(): string[];

    abstract resolve(hostname: string, rrtype?: "A"|"AAAA"|"CNAME"|"NS"|"PTR"): Promise<string[]>;
    abstract resolve(hostname: string, rrtype: "ANY"): Promise<DNSRecord[]>;
    abstract resolve(hostname: string, rrtype: "CAA"): Promise<{ critical: number; iodef?: string; issue?: string }[]>;
    abstract resolve(hostname: string, rrtype: "MX"): Promise<{ priority: number; exchange: string }[]>;
    abstract resolve(hostname: string, rrtype: "NAPTR"): Promise<NAPTRRecord[]>;
    abstract resolve(hostname: string, rrtype: "SOA"): Promise<SOARecord>;
    abstract resolve(hostname: string, rrtype: "SRV"): Promise<SRVRecord>;
    abstract resolve(hostname: string, rrtype: "TXT"): Promise<string[][]>;
    abstract resolve(hostname: string, rrtype?: "A" | "AAAA" | "ANY" | "CAA" | "CNAME" | "MX" | "NAPTR" | "NS" | "PTR" | "SOA" | "SRV" | "TXT"): Promise<string[] | DNSRecord[] | { critical: number; iodef?: string; issue?: string }[] | { priority: number; exchange: string }[] | NAPTRRecord[] | SOARecord | SRVRecord | string[][]>;

    resolve4(hostname: string, options: { ttl: true }): Promise<ARecord[]>;
    resolve4(hostname: string, options?: { ttl: false }): Promise<string[]>;
    resolve4(hostname: string, options?: { ttl: boolean }): Promise<string[] | ARecord[]> {
        return this.resolve(hostname, 'A');
    }

    resolve6(hostname: string, options: { ttl: true }): Promise<AAAARecord[]>;
    resolve6(hostname: string, options?: { ttl: false }): Promise<string[]>;
    resolve6(hostname: string, options?: { ttl: boolean }): Promise<string[] | AAAARecord[]> {
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

    async lookup(hostname: string, options: 4 | 6 | { family: 4 | 6 | 0, hints: number, all: boolean, verbatim: boolean } = 4): Promise<{address: string, family: number} | { address: string, family: number }[]> {
        let result: {address: string, family: number}[] = [];
        let family;
        let hints = 0;
        let all = false;
        let verbatim = false;
        if (typeof options === 'object') {({family, hints, all, verbatim} = options)}

        if (family === 6 || family === 0) {
            result = (await this.resolve(hostname, 'AAAA')).map(v=>({address: v, family: 6}));
        }
        // TODO hints, all, verbatim
        result.concat((await this.resolve(hostname, 'A')).map(v=>({address: v, family: 4})));

        if (family === 4) return result[0];
        return result;

    }

    lookupService(address: string, port: number): Promise<{hostname: string, service: string}> {
        throw new DNSError("not implemented", NOTIMP);
    }
}
