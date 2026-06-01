import {BaseResolver} from "../src/base_resolver.js";
import {AnswerRecord, DNSResponse, Question} from "../src/rfc1035.js";
import {ALGORITHMS, CLASS, DIGESTS, RecordType} from "../src/constants.js";
import {ResolveOptions} from "../src/dns.js";
import {expect} from "chai";
import {RDATA} from "../src/rfc_rdata.js";

export default class FakeResolver extends BaseResolver {
    public keys: Record<string, CryptoKeyPair>;
    public pubkeys: Record<string, ArrayBuffer>;
    public ttl = 10;
    public called = 0;
    public expectedHostname?: string = undefined;
    public zones?: string[];
    public responseCallback = (response: DNSResponse) => response;

    public static async build(domains: string[], algorithm: number = 13) {
        const resolver = new this();
        resolver.zones = domains;
        const keys = await Promise.all(domains.map(domain => crypto.subtle.generateKey(ALGORITHMS[algorithm], true, ["verify", "sign"]) as Promise<CryptoKeyPair>));
        resolver.keys = Object.fromEntries(domains.map((domain, i) => [domain, keys[i]]));
        const pubkeysData = await Promise.all(Object.values(keys).map(async (v) => {
            const k = await crypto.subtle.exportKey('raw', v.publicKey);
            if (k.byteLength % 2 === 1) return k.slice(1); // trim undocumented byte from beginning. Modulus?
            return k;
        }));
        resolver.pubkeys = Object.fromEntries(pubkeysData.map((v, i) => [domains[i], v]));
        return resolver;
    }

    cancel(): void {
        throw new Error('Method not implemented.');
    }

    async resolve(hostname: string | {
        hostname: string,
        rrtype: (keyof typeof RecordType)
    }[], rrtype?: (keyof typeof RecordType) | "ANY" | ResolveOptions, options?: ResolveOptions): Promise<any> {
        this.called += 1;
        expect(rrtype).to.be.oneOf(["DS", "DNSKEY", "SOA"]);
        expect(options.dnssec, 'DNSSEC must be enabled').to.be.true;
        expect(options.raw, 'Raw response expected').to.be.true;
        expect(typeof hostname, 'hostname is not a string').to.eq('string');
        let trimmedHostname = (hostname as string).replace(/\.$/, '').toLowerCase();
        if (trimmedHostname.endsWith("example.com")) trimmedHostname = "example.com";
        if (["DS", "DNSKEY"].includes(rrtype as string)) expect(this.pubkeys).to.haveOwnProperty(trimmedHostname);
        if (this.expectedHostname) expect(hostname, 'unexpected hostname when requesting DS for KSK').to.eq(this.expectedHostname);
        switch (rrtype) {
            case "DS":
                // digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
                // DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.  "|" denotes concatenation
                const digestData = [
                    ...trimmedHostname.split('.').flatMap(s => [s.length, ...Uint8Array.from(s, c => c.charCodeAt(0))]),
                    0,                                   // ''
                    256,                                 // flags
                    3,                                   // protocol
                    13,                                  // algorithm
                    ...new Uint8Array(this.pubkeys[trimmedHostname]),
                ];
                const rdata = {
                    key_tag: 0,
                    algorithm: 13,
                    digest_type: 2,
                    digest: await crypto.subtle.digest(DIGESTS[2], Uint8Array.from(digestData).buffer),
                } as RDATA[RecordType.DS];
                return this.responseCallback({
                    header: {},
                    question: [{} as Question],
                    answer: [{
                        NAME: [...trimmedHostname.split('.'), ''],
                        TYPE: RecordType.DS,
                        CLASS: CLASS.IN,
                        TTL: this.ttl,
                        RDATA: rdata,
                        RDLENGTH: 4 + rdata.digest.byteLength,
                        raw_rdata: Uint8Array.from([0, rdata.key_tag, rdata.algorithm, rdata.digest_type, ...new Uint8Array(rdata.digest)]).buffer
                    } as AnswerRecord<RecordType.DS>],
                    additional: [],
                    authority: [],
                } as DNSResponse);
            case "DNSKEY":
                return this.responseCallback({
                    header: {},
                    question: [{} as Question],
                    answer: [{
                        NAME: [...trimmedHostname.split('.'), ''],
                        TYPE: RecordType.DNSKEY,
                        CLASS: CLASS.IN,
                        TTL: this.ttl,
                        RDATA: {
                            key_tag: 0,
                            algorithm: 13,
                            protocol: 3,
                            zone_key: true,
                            secure_entry_point: false,
                            public_key: this.pubkeys[trimmedHostname],
                        },
                        RDLENGTH: 4 + this.pubkeys[trimmedHostname].byteLength,
                        raw_rdata: Uint8Array.from([256, 3, 13, ...new Uint8Array(this.pubkeys[trimmedHostname])]).buffer
                    } as AnswerRecord<RecordType.DNSKEY>],
                    additional: [],
                    authority: [],
                } as DNSResponse);
            case "SOA":
                return this.responseCallback({
                    header: {},
                    question: [{} as Question],
                    answer: [{
                        NAME: [...trimmedHostname.split('.'), ''],
                        TYPE: RecordType.SOA,
                        CLASS: CLASS.IN,
                        TTL: this.ttl,
                        RDATA: {},
                        RDLENGTH: 0,
                        raw_rdata: undefined,
                    } as AnswerRecord<RecordType.SOA>],
                    additional: [],
                    authority: [],
                } as DNSResponse)
        }
    }

    protected servers: string[];
}