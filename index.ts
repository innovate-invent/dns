import {
    Resolver as IResolver,
    promises,
    DNSRecord,
    NAPTRRecord,
    SOARecord,
    SRVRecord,
    ARecord,
    AAAARecord,
    DNSError, LookupCallback, LookupCallbackAll
} from './dns'
import CFResolver from './cloudflare'
import * as constants from './constants'


class Resolver implements IResolver {
    _resolver: promises.Resolver;

    constructor(options: { timeout: number; }, baseType: IResolver = CFResolver) {
        this._resolver = new baseType(options);
    }

    cancel(): void {
        this._resolver.cancel();
    }

    getServers(): string[] {
        return this._resolver.getServers();
    }

    resolve(hostname: string, callback: (err?: DNSError, records?: string[]) => void): void;
    resolve(hostname: string, rrtype: "A", callback: (err?: DNSError, records?: string[]) => void): void;
    resolve(hostname: string, rrtype: "AAAA", callback: (err?: DNSError, records?: string[]) => void): void;
    resolve(hostname: string, rrtype: "ANY", callback: (err?: DNSError, records?: DNSRecord[]) => void): void;
    resolve(hostname: string, rrtype: "CAA", callback: (err?: DNSError, records?: { critical: number; iodef?: string; issue?: string }[]) => void): void;
    resolve(hostname: string, rrtype: "CNAME", callback: (err?: DNSError, records?: string[]) => void): void;
    resolve(hostname: string, rrtype: "MX", callback: (err?: DNSError, records?: { priority: number; exchange: string }[]) => void): void;
    resolve(hostname: string, rrtype: "NAPTR", callback: (err?: DNSError, records?: NAPTRRecord[]) => void): void;
    resolve(hostname: string, rrtype: "NS", callback: (err?: DNSError, records?: string[]) => void): void;
    resolve(hostname: string, rrtype: "PTR", callback: (err?: DNSError, records?: string[]) => void): void;
    resolve(hostname: string, rrtype: "SOA", callback: (err?: DNSError, records?: SOARecord) => void): void;
    resolve(hostname: string, rrtype: "SRV", callback: (err?: DNSError, records?: SRVRecord) => void): void;
    resolve(hostname: string, rrtype: "TXT", callback: (err?: DNSError, records?: string[][]) => void): void;
    resolve(hostname: string, ...args: any[]): void {
        const callback = args.pop();
        this._resolver.resolve(hostname, args[0]).then(v=>callback(null, v)).catch(e=>callback(e, null));
    }

    resolve4(hostname: string, callback: (err?: DNSError, address?: string[]) => void): void;
    resolve4(hostname: string, options: { ttl: true }, callback: (err?: DNSError, address?: ARecord[]) => void): void;
    resolve4(hostname: string, options: { ttl: false }, callback: (err?: DNSError, address?: string[]) => void): void;
    resolve4(hostname: string, ...args: any[]): void {
        const callback = args.pop();
        this._resolver.resolve4(hostname, args[0]).then(v=>callback(null, v)).catch(e=>callback(e, null));
    }

    resolve6(hostname: string, callback: (err?: DNSError, address?: string[]) => void): void;
    resolve6(hostname: string, options: { ttl: true }, callback: (err?: DNSError, address?: AAAARecord[]) => void): void;
    resolve6(hostname: string, options: { ttl: false }, callback: (err?: DNSError, address?: string[]) => void): void;
    resolve6(hostname: string, ...args: any[]): void {
        const callback = args.pop();
        this._resolver.resolve6(hostname, args[0]).then(v=>callback(null, v)).catch(e=>callback(e, null));
    }

    resolveAny(hostname: string, callback: (err?: DNSError, ret?: DNSRecord[]) => void): void {
        this._resolver.resolveAny(hostname).then(v=>callback(null, v)).catch(e=>callback(e, null));
    }

    resolveCaa(hostname: string, callback: (err?: DNSError, records?: { critical: number; iodef?: string; issue?: string }[]) => void): void {
        this._resolver.resolveCaa(hostname).then(v=>callback(null, v)).catch(e=>callback(e, null));
    }

    resolveCname(hostname: string, callback: (err?: DNSError, addresses?: string[]) => void): void {
        this._resolver.resolveCname(hostname).then(v=>callback(null, v)).catch(e=>callback(e, null));
    }

    resolveMx(hostname: string, callback: (err?: DNSError, addresses?: { priority: number; exchange: string }[]) => void): void {
        this._resolver.resolveMx(hostname).then(v=>callback(null, v)).catch(e=>callback(e, null));
    }

    resolveNaptr(hostname: string, callback: (err?: DNSError, addresses?: NAPTRRecord[]) => void): void {
        this._resolver.resolveNaptr(hostname).then(v=>callback(null, v)).catch(e=>callback(e, null));
    }

    resolveNs(hostname: string, callback: (err?: DNSError, addresses?: string[]) => void): void {
        this._resolver.resolveNs(hostname).then(v=>callback(null, v)).catch(e=>callback(e, null));
    }

    resolvePtr(hostname: string, callback: (err?: DNSError, addresses?: string[]) => void): void {
        this._resolver.resolvePtr(hostname).then(v=>callback(null, v)).catch(e=>callback(e, null));
    }

    resolveSoa(hostname: string, callback: (err?: DNSError, address?: SOARecord) => void): void {
        this._resolver.resolveSoa(hostname).then(v=>callback(null, v)).catch(e=>callback(e, null));
    }

    resolveSrv(hostname: string, callback: (err?: DNSError, addresses?: SRVRecord) => void): void {
        this._resolver.resolveSrv(hostname).then(v=>callback(null, v)).catch(e=>callback(e, null));
    }

    resolveTxt(hostname: string, callback: (err?: DNSError, records?: string[][]) => void): void {
        this._resolver.resolveTxt(hostname).then(v=>callback(null, v)).catch(e=>callback(e, null));
    }

    reverse(hostname: string, callback: (err?: DNSError, hostnames?: string[]) => void): void {
        this._resolver.reverse(hostname).then(v=>callback(null, v)).catch(e=>callback(e, null));
    }

    setLocalAddress(ipv4: string, ipv6: string): void {
        this._resolver.setLocalAddress(ipv4, ipv6)
    }

    setServers(servers: string[]): void {
        this._resolver.setServers(servers);
    }
}

function lookup(hostname: string, callback: LookupCallback): void;
function lookup(hostname: string, options: 4 | 6 | { family: 4 | 6 | 0, hints: number, all: boolean, verbatim: boolean }, callback: LookupCallback | LookupCallbackAll): void;
function lookup(hostname: string, ...args: any[]): void {
    const callback = args.pop();
    defaultPromiseResolver.lookup(hostname, args[0]).then(v=>Array.isArray(v)?callback(undefined, v) : callback(undefined, v.address, v.family)).catch(e=>callback(e));
}

function lookupService(address: string, port: number, callback: (err?: DNSError, hostname?: string, service?: string)=>void): void {
    defaultPromiseResolver.lookupService(address, port).then(v=>callback(undefined, v.hostname, v.service)).catch(e=>callback(e));
}

const defaultResolver = new Resolver({timeout: -1}, CFResolver);
const defaultPromiseResolver = new CFResolver();

export = {
    ...constants,
    Resolver,
    promises: {
        Resolver: CFResolver,
        getServers: defaultPromiseResolver.getServers,
        lookup: defaultPromiseResolver.lookup,
        lookupService: defaultPromiseResolver.lookupService,
        resolve: defaultPromiseResolver.resolve,
        resolve4: defaultPromiseResolver.resolve4,
        resolve6: defaultPromiseResolver.resolve6,
        resolveAny: defaultPromiseResolver.resolveAny,
        resolveCname: defaultPromiseResolver.resolveCname,
        resolveCaa: defaultPromiseResolver.resolveCaa,
        resolveMx: defaultPromiseResolver.resolveMx,
        resolveNaptr: defaultPromiseResolver.resolveNaptr,
        resolveNs: defaultPromiseResolver.resolveNs,
        resolvePtr: defaultPromiseResolver.resolvePtr,
        resolveSoa: defaultPromiseResolver.resolveSoa,
        resolveSrv: defaultPromiseResolver.resolveSrv,
        resolveTxt: defaultPromiseResolver.resolveTxt,
        reverse: defaultPromiseResolver.reverse,
        setServers: defaultPromiseResolver.setServers,
    },
    getServers: defaultResolver.getServers,
    lookup,
    lookupService,
    resolve: defaultResolver.resolve,
    resolve4: defaultResolver.resolve4,
    resolve6: defaultResolver.resolve6,
    resolveAny: defaultResolver.resolveAny,
    resolveCname: defaultResolver.resolveCname,
    resolveCaa: defaultResolver.resolveCaa,
    resolveMx: defaultResolver.resolveMx,
    resolveNaptr: defaultResolver.resolveNaptr,
    resolveNs: defaultResolver.resolveNs,
    resolvePtr: defaultResolver.resolvePtr,
    resolveSoa: defaultResolver.resolveSoa,
    resolveSrv: defaultResolver.resolveSrv,
    resolveTxt: defaultResolver.resolveTxt,
    reverse: defaultResolver.reverse,
    setServers: defaultResolver.setServers,
}
