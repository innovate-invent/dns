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

    /*
    hostname <string>
    options <integer> | <Object>
        family <integer> The record family. Must be 4, 6, or 0. The value 0 indicates that IPv4 and IPv6 addresses are both returned. Default: 0.
        hints <number> One or more supported getaddrinfo flags. Multiple flags may be passed by bitwise ORing their values.
        all <boolean> When true, the callback returns all resolved addresses in an array. Otherwise, returns a single address. Default: false.
        verbatim <boolean> When true, the callback receives IPv4 and IPv6 addresses in the order the DNS resolver returned them. When false, IPv4 addresses are placed before IPv6 addresses. Default: currently false (addresses are reordered) but this is expected to change in the not too distant future. New code should use { verbatim: true }.
    callback <Function>
        err <Error>
        address <string> A string representation of an IPv4 or IPv6 address.
        family <integer> 4 or 6, denoting the family of address, or 0 if the address is not an IPv4 or IPv6 address. 0 is a likely indicator of a bug in the name resolution service used by the operating system.

    Resolves a host name (e.g. 'nodejs.org') into the first found A (IPv4) or AAAA (IPv6) record. All option properties are optional. If options is an integer, then it must be 4 or 6 – if options is not provided, then IPv4 and IPv6 addresses are both returned if found.

    With the all option set to true, the arguments for callback change to (err, addresses), with addresses being an array of objects with the properties address and family.

    On error, err is an Error object, where err.code is the error code. Keep in mind that err.code will be set to 'ENOTFOUND' not only when the host name does not exist but also when the lookup fails in other ways such as no available file descriptors.
     */
    async lookup(hostname: string, options: 4 | 6 | { family: 4 | 6 | 0, hints?: number, all?: boolean, verbatim?: boolean } = 4): Promise<{address: string, family: number} | { address: string, family: number }[]> {
        let result: {address: string, family: number}[] = [];
        let family: number = options as number;
        let hints = 0; // Ignored, not supported
        let all = false;
        let verbatim = false; // Ignored, always false
        if (typeof options === 'object') {
            family = options.family || family;
            hints = options.hints || hints;
            all = options.all || all;
            verbatim = options.verbatim || verbatim;
        }

        if (family === 6 || family === 0) {
            result = (await this.resolve(hostname, 'AAAA')).map(v=>({address: v, family: 6}));
        }

        if (family === 4 || family === 0) {
            result = result.concat((await this.resolve(hostname, 'A')).map(v => ({address: v, family: 4})));
        }

        if (result.length === 0) throw DNSError.NODATA;
        if (!all) return result[0];
        return result;

    }

    lookupService(address: string, port: number): Promise<{hostname: string, service: string}> {
        throw DNSError.NOTIMP;
    }
}
