/**
 * RFC8484 DoH Resolver
 * https://tools.ietf.org/html/rfc8484
 */

import {parseResponse, DNSResponse as DNSResponse, WireFormatResolver} from "./rfc1035.js";
import {base64url_encode} from "./base64url";
import {BaseResolverOptions} from "./base_resolver";

export default class Resolver extends WireFormatResolver {
    protected servers: string[] = ['cloudflare-dns.com', 'doh.opendns.com', 'unfiltered.adguard-dns.com', 'dns.google', 'dns.quad9.net'];
    protected _fetch = window ? window.fetch.bind(window) : fetch;

    constructor(options?: BaseResolverOptions & {fetch?: typeof fetch}) {
        super(options)
        if (options && options.fetch) this._fetch = options.fetch;
    }

    async _submit(server: string, request: ArrayBuffer, keepRDATA: boolean = false, abortSignal: AbortSignal): Promise<[DNSResponse, ArrayBuffer]> {
        const payload = base64url_encode(request);
        const rawResponse = await this._fetch(this._url(server, payload), {
            headers: new Headers({'accept': 'application/dns-message'}),
            signal: abortSignal,
        });
        const rawResponseData = await rawResponse.arrayBuffer();
        return [parseResponse(rawResponseData, keepRDATA), rawResponseData];
    }
}
