/**
 * RFS8484 DoH Resolver
 * https://tools.ietf.org/html/rfc8484
 */

import {BaseResolver} from './base_resolver.js'
import {DNSError, ResolveOptions,} from './dns.js'
import {RecordType} from "./constants.js";
import {buildRequest, parseResponse, Question} from "./rfc1035.js";
import validate from "./rfc4034.js";
import {base64url_encode} from "./base64url.js"
import {toNodeJSResponse} from "./nodejs";

const CACHE_NAME = '@i2labs.ca/dns';

export default class Resolver extends BaseResolver {
    protected servers: string[] = ['cloudflare-dns.com'];

    async resolve(hostname: string, rrtype?: (keyof typeof RecordType) | "ANY", options?: ResolveOptions): Promise<any> {
        if (rrtype === "ANY") rrtype = "*";
        else if (rrtype === undefined) rrtype = 'A';
        const question = new Question(hostname.split('.'), RecordType[rrtype as keyof typeof RecordType]);
        const payload = base64url_encode(buildRequest([question], undefined, options && options.dnssec));
        const url = `https://${this.getServers()[0]}/dns-query?dns=${payload}`;
        let rawResponse: Response;

        // Check cached records
        const cache = await caches.open(CACHE_NAME);
        rawResponse = await cache.match(url);
        if (rawResponse) {
            const expires = rawResponse.headers.get('Expires');
            if (!expires || new Date(expires) < new Date()) {
                cache.delete(url);
                rawResponse = null;
            }
        }

        // Fetch records on cache miss
        if (!rawResponse) {
            rawResponse = await this._fetch(url, {headers: new Headers({'accept': 'application/dns-message'})});
        }

        const response = await parseResponse(await (rawResponse.clone().arrayBuffer()), options && options.dnssec);
        if (!response.answer || response.answer.length === 0) throw DNSError.NODATA;
        if (response.question && response.question.length === 1) { // verify question
            const q = response.question[0];
            if (Object.entries(question).some(([k,v])=>Array.isArray(v) ? v.some((e, i)=>e !== (q[k as keyof Question] as any[])[i]) : q[k as keyof Question] !== v)) throw new Error('DNS query in response does not match original query');
        } else throw new Error('Unable to validate DNS query from response');

        // Cache response with expires set to the smallest record TTL
        const minTTL = response.answer.reduce((acc, cur)=>acc > cur.TTL ? cur.TTL : acc, 604800);
        rawResponse = new Response(rawResponse.body, {
            status: rawResponse.status,
            statusText: rawResponse.statusText,
            headers: new Headers(rawResponse.headers),
        });
        rawResponse.headers.set('Expires', new Date(Date.now() + (minTTL * 1000)).toUTCString());
        cache.put(url, rawResponse);

        if (options && options.dnssec && !await validate(response, this)) throw new Error(`DNSSEC validation for ${rrtype} from ${hostname} failed`); // verify DNSSEC
        if (options && options.raw) return response;

        return toNodeJSResponse(response.answer, rrtype, options);
    }
}
