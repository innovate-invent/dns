/**
 * RFC8484 DoH Resolver
 * https://tools.ietf.org/html/rfc8484
 */

import {parseResponse, DNSResponse as DNSResponse, WireFormatResolver} from "./rfc1035.js";
import FetchContext from "./FetchContext";
import {BaseResolverOptions} from "./base_resolver";
import {base64url_encode} from "./base64url";

export default class Resolver extends WireFormatResolver {
    protected servers: string[] = ['cloudflare-dns.com', 'doh.opendns.com', 'unfiltered.adguard-dns.com', 'dns.google', 'dns.quad9.net'];
    protected readonly fetchContext: FetchContext;

    constructor(options?: BaseResolverOptions) {
        super(options);
        this.fetchContext = new FetchContext(this._timeout, this._tries);
    }

    async _submit(server: string, request: ArrayBuffer, keepRDATA: boolean = false): Promise<[DNSResponse, ArrayBuffer]> {
        const payload = base64url_encode(request);
        const url = `https://${server}/dns-query?dns=${payload}`;
        const rawResponse = await this.fetchContext.fetch(url, {headers: new Headers({'accept': 'application/dns-message'})});
        const rawResponseData = await rawResponse.arrayBuffer();
        return [parseResponse(rawResponseData, keepRDATA), rawResponseData];
    }

    cancel() {
        this.fetchContext.cancel();
    }
}
