import {
    Resolver,
    PromiseResolver,
    DNSRecord,
    NAPTRRecord,
    SOARecord,
    SRVRecord,
    ARecord,
    AAAARecord,
    DNSError, LookupCallback, LookupCallbackAll, AnyDNSRecord
} from './dns.js'
import RFCResolver from './rfc8484.js'
import * as constants from './constants.js'

/**
 * Wrapper around Promise based Resolver implementations to support callback interface.
 * Pass an instantiated PromiseResolver to constructor to wrap the resolver.
 * Defaults to CloudFlare resolver.
 */
class CallbackResolver implements Resolver {
    _resolver: PromiseResolver;

    constructor(options?: { timeout: number; } | PromiseResolver) {
        if (options === undefined) {
            this._resolver = new RFCResolver();
        } else if ('timeout' in options) {
            this._resolver = new RFCResolver(options);
        } else {
            this._resolver = options;
        }
    }

    cancel(): void {
        this._resolver.cancel();
    }

    getServers(): string[] {
        return this._resolver.getServers();
    }

    resolve(hostname: string, ...args: any[]): void {
        const callback = args.pop();
        this._resolver.resolve(hostname, args[0]).then(v=>callback(undefined, v)).catch(e=>callback(e, undefined));
    }

    resolve4(hostname: string, callback: (err?: DNSError, address?: string[]) => void): void;
    resolve4(hostname: string, options: { ttl: true }, callback: (err?: DNSError, address?: ARecord[]) => void): void;
    resolve4(hostname: string, options: { ttl: false }, callback: (err?: DNSError, address?: string[]) => void): void;
    resolve4(hostname: string, ...args: any[]): void {
        const callback = args.pop();
        this._resolver.resolve4(hostname, args[0]).then(v=>callback(undefined, v)).catch(e=>callback(e, undefined));
    }

    resolve6(hostname: string, callback: (err?: DNSError, address?: string[]) => void): void;
    resolve6(hostname: string, options: { ttl: true }, callback: (err?: DNSError, address?: AAAARecord[]) => void): void;
    resolve6(hostname: string, options: { ttl: false }, callback: (err?: DNSError, address?: string[]) => void): void;
    resolve6(hostname: string, ...args: any[]): void {
        const callback = args.pop();
        this._resolver.resolve6(hostname, args[0]).then(v=>callback(undefined, v)).catch(e=>callback(e, undefined));
    }

    resolveAny(hostname: string, callback: (err?: DNSError, ret?: AnyDNSRecord[]) => void): void {
        this._resolver.resolveAny(hostname).then(v=>callback(undefined, v)).catch(e=>callback(e, undefined));
    }

    resolveCaa(hostname: string, callback: (err?: DNSError, records?: { critical: number; iodef?: string; issue?: string }[]) => void): void {
        this._resolver.resolveCaa(hostname).then(v=>callback(undefined, v)).catch(e=>callback(e, undefined));
    }

    resolveCname(hostname: string, callback: (err?: DNSError, addresses?: string[]) => void): void {
        this._resolver.resolveCname(hostname).then(v=>callback(undefined, v)).catch(e=>callback(e, undefined));
    }

    resolveMx(hostname: string, callback: (err?: DNSError, addresses?: { priority: number; exchange: string }[]) => void): void {
        this._resolver.resolveMx(hostname).then(v=>callback(undefined, v)).catch(e=>callback(e, undefined));
    }

    resolveNaptr(hostname: string, callback: (err?: DNSError, addresses?: NAPTRRecord[]) => void): void {
        this._resolver.resolveNaptr(hostname).then(v=>callback(undefined, v)).catch(e=>callback(e, undefined));
    }

    resolveNs(hostname: string, callback: (err?: DNSError, addresses?: string[]) => void): void {
        this._resolver.resolveNs(hostname).then(v=>callback(undefined, v)).catch(e=>callback(e, undefined));
    }

    resolvePtr(hostname: string, callback: (err?: DNSError, addresses?: string[]) => void): void {
        this._resolver.resolvePtr(hostname).then(v=>callback(undefined, v)).catch(e=>callback(e, undefined));
    }

    resolveSoa(hostname: string, callback: (err?: DNSError, address?: SOARecord) => void): void {
        this._resolver.resolveSoa(hostname).then(v=>callback(undefined, v)).catch(e=>callback(e, undefined));
    }

    resolveSrv(hostname: string, callback: (err?: DNSError, addresses?: SRVRecord[]) => void): void {
        this._resolver.resolveSrv(hostname).then(v=>callback(undefined, v)).catch(e=>callback(e, undefined));
    }

    resolveTxt(hostname: string, callback: (err?: DNSError, records?: string[][]) => void): void {
        this._resolver.resolveTxt(hostname).then(v=>callback(undefined, v)).catch(e=>callback(e, undefined));
    }

    reverse(hostname: string, callback: (err?: DNSError, hostnames?: string[]) => void): void {
        this._resolver.reverse(hostname).then(v=>callback(undefined, v)).catch(e=>callback(e, undefined));
    }

    setLocalAddress(ipv4: string, ipv6: string): void {
        this._resolver.setLocalAddress(ipv4, ipv6)
    }

    setServers(servers: string[]): void {
        this._resolver.setServers(servers);
    }
}

const defaultResolver = new CallbackResolver();
const defaultPromiseResolver = new RFCResolver();

type LookupResult = { address: string, family: number };

function lookupPromise(hostname: string, options?: 4 | 6 | { family: 4 | 6 | 0, hints?: number, all?: false, verbatim?: boolean }): Promise<LookupResult>;
function lookupPromise(hostname: string, options: { family: 4 | 6 | 0, hints?: number, all: true, verbatim?: boolean }): Promise<LookupResult[]>;
function lookupPromise(hostname: string, ...args: any[]): Promise<LookupResult | LookupResult[]> {
    const options = args[0];
    let family: number = options as number || 4;
    let hints = 0; // Ignored, not supported
    let all = false;
    let verbatim = false; // Ignored, always false
    if (typeof options === 'object') {
        family = options.family || family;
        hints = options.hints || hints;
        all = options.all || all;
        verbatim = options.verbatim || verbatim;
    }
    let promise = Promise.resolve([]);
    if (family === 6 || family === 0) {
        promise = defaultPromiseResolver.resolve(hostname, 'AAAA').then(r=>r.map((v: string)=>({address: v, family: 6})));
    }

    if (family === 4 || family === 0) {
        promise = Promise.all([promise, defaultPromiseResolver.resolve(hostname, 'A').then(r=>r.map((v: string)=>({address: v, family: 4})))]).then(r=>r[0].concat(r[1]));
    }

    return promise.then(result=>{
        if (result.length === 0) throw DNSError.NODATA;
        return all ? result : result[0];
    });
}

function lookupServicePromise(address: string, port: number): Promise<{hostname: string, service: string}> {
    throw DNSError.NOTIMP;
}

function lookup(hostname: string, callback: LookupCallback): void;
function lookup(hostname: string, options: 4 | 6 | { family: 4 | 6 | 0, hints?: number, all?: boolean, verbatim?: boolean }, callback: LookupCallback | LookupCallbackAll): void;
function lookup(hostname: string, ...args: any[]): void {
    const callback = args.pop();
    lookupPromise(hostname, args[0]).then(result=>Array.isArray(result) ? callback(undefined, result) : callback(undefined, result.address, result.family)).catch(err=>callback(err));
}

function lookupService(address: string, port: number, callback: (err?: DNSError, hostname?: string, service?: string)=>void): void {
    lookupServicePromise(address, port).then(v=>callback(undefined, v.hostname, v.service)).catch(e=>callback(e));
}

export default {
    ...constants,
    Resolver: CallbackResolver,
    promises: {
        Resolver: RFCResolver,
        lookup: lookupPromise,
        lookupService: lookupServicePromise,
        getServers: defaultPromiseResolver.getServers.bind(defaultPromiseResolver),
        resolve: defaultPromiseResolver.resolve.bind(defaultPromiseResolver),
        resolve4: defaultPromiseResolver.resolve4.bind(defaultPromiseResolver),
        resolve6: defaultPromiseResolver.resolve6.bind(defaultPromiseResolver),
        resolveAny: defaultPromiseResolver.resolveAny.bind(defaultPromiseResolver),
        resolveCname: defaultPromiseResolver.resolveCname.bind(defaultPromiseResolver),
        resolveCaa: defaultPromiseResolver.resolveCaa.bind(defaultPromiseResolver),
        resolveMx: defaultPromiseResolver.resolveMx.bind(defaultPromiseResolver),
        resolveNaptr: defaultPromiseResolver.resolveNaptr.bind(defaultPromiseResolver),
        resolveNs: defaultPromiseResolver.resolveNs.bind(defaultPromiseResolver),
        resolvePtr: defaultPromiseResolver.resolvePtr.bind(defaultPromiseResolver),
        resolveSoa: defaultPromiseResolver.resolveSoa.bind(defaultPromiseResolver),
        resolveSrv: defaultPromiseResolver.resolveSrv.bind(defaultPromiseResolver),
        resolveTxt: defaultPromiseResolver.resolveTxt.bind(defaultPromiseResolver),
        reverse: defaultPromiseResolver.reverse.bind(defaultPromiseResolver),
        setServers: defaultPromiseResolver.setServers.bind(defaultPromiseResolver),
    },
    lookup,
    lookupService,
    getServers: defaultResolver.getServers.bind(defaultResolver),
    resolve: defaultResolver.resolve.bind(defaultResolver),
    resolve4: defaultResolver.resolve4.bind(defaultResolver),
    resolve6: defaultResolver.resolve6.bind(defaultResolver),
    resolveAny: defaultResolver.resolveAny.bind(defaultResolver),
    resolveCname: defaultResolver.resolveCname.bind(defaultResolver),
    resolveCaa: defaultResolver.resolveCaa.bind(defaultResolver),
    resolveMx: defaultResolver.resolveMx.bind(defaultResolver),
    resolveNaptr: defaultResolver.resolveNaptr.bind(defaultResolver),
    resolveNs: defaultResolver.resolveNs.bind(defaultResolver),
    resolvePtr: defaultResolver.resolvePtr.bind(defaultResolver),
    resolveSoa: defaultResolver.resolveSoa.bind(defaultResolver),
    resolveSrv: defaultResolver.resolveSrv.bind(defaultResolver),
    resolveTxt: defaultResolver.resolveTxt.bind(defaultResolver),
    reverse: defaultResolver.reverse.bind(defaultResolver),
    setServers: defaultResolver.setServers.bind(defaultResolver),
}
