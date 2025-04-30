/**
 * Various DNS record type queries and their expected parsed response values for use in the test suite
 */

import {RecordType} from "../src/constants.js";
import {ResolveOptions} from "../src/dns";

export type Expected = {host: string, records: any[], cmp?: string[], pending?: boolean, options?: ResolveOptions, raw?: string};

// 'raw' values are the base64url encoded response body for each request fetched from the test DNS records hosted on Cloudflare.
// This to prevent test failures as Cloudflare seems to be dropping support for some record types.

// TODO error codes
export const nodeTypes = { // The expected values here should be identical to what NodeJS DNS returns
    "SOA": {
        host: "i2labs.ca.",
        records: [{
            expire: 604800,
            hostmaster: "dns.cloudflare.com",
            minttl: 1800,
            nsname: "isla.ns.cloudflare.com",
            refresh: 10000,
            retry: 2400,
            serial: 2036371151
        }],
        cmp: ["nsname", "hostmaster", "refresh", "minttl", "expire", "retry"],
        raw: "AACBgAABAAEAAAAABmkybGFicwJjYQAABgABwAwABgABAAAHCAAyBGlzbGECbnMKY2xvdWRmbGFyZQNjb20AA2Ruc8AvjRwMhAAAJxAAAAlgAAk6gAAABwg",
    },
    "A": {host: "example.i2labs.ca.", records: ["0.0.0.0"], raw: "AACBgAABAAEAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAAABAAHADAABAAEAAAEsAAQAAAAA"},
    "AAAA": {host: "example.i2labs.ca.", records: ["2001:db8:85a3::8a2e:370:7334", "::"], raw: "AACBgAABAAIAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAAAcAAHADAAcAAEAAAEsABAAAAAAAAAAAAAAAAAAAAAAwAwAHAABAAABLAAQIAENuIWjAAAAAIouA3BzNA"},
    "CNAME": {host: "cname.example.i2labs.ca.", records: ["example.i2labs.ca"], raw: "AACBgAABAAEAAAAABWNuYW1lB2V4YW1wbGUGaTJsYWJzAmNhAAAFAAHADAAFAAEAAAEsAALAEg"},
    "CAA": {
        host: "cname.example.i2labs.ca.",
        records: [{critical: 0, issue: "example.org"}],
        cmp: ["critical", "issue"],
        raw: "AACBgAABAAIAAAAABWNuYW1lB2V4YW1wbGUGaTJsYWJzAmNhAAEBAAHADAAFAAEAAAEsAALAEsASAQEAAQAAASwAEgAFaXNzdWVleGFtcGxlLm9yZw"
    },
    "MX": {
        host: "example.i2labs.ca.",
        records: [{priority: 0, exchange: "example.org"}],
        cmp: ["priority", "exchange"],
        raw: "AACBgAABAAEAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAAAPAAHADAAPAAEAAAEsAA8AAAdleGFtcGxlA29yZwA"
    },
    "NS": {
        host: "cloudflare.com",
        records: ["ns3.cloudflare.com", "ns4.cloudflare.com", "ns5.cloudflare.com", "ns6.cloudflare.com", "ns7.cloudflare.com"],
        raw: "AACBgAABAAUAAAAACmNsb3VkZmxhcmUDY29tAAACAAHADAACAAEAAVGAAAYDbnMzwAzADAACAAEAAVGAAAYDbnM0wAzADAACAAEAAVGAAAYDbnM1wAzADAACAAEAAVGAAAYDbnM2wAzADAACAAEAAVGAAAYDbnM3wAw"
    },
    "SRV": {
        host: "_example._tcp.example.i2labs.ca.",
        records: [{priority: 0, weight: 0, port: 0, name: "example.org"}],
        cmp: ["priority", "weight", "port", "name"],
        raw: "AACBgAABAAEAAAAACF9leGFtcGxlBF90Y3AHZXhhbXBsZQZpMmxhYnMCY2EAACEAAcAMACEAAQAAASwAEwAAAAAAAAdleGFtcGxlA29yZwA"
    },
    "PTR": {host: "example.i2labs.ca.", records: ["example.org"], raw: "AACBgAABAAEAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAAAMAAHADAAMAAEAAAEsAA0HZXhhbXBsZQNvcmcA"},
    "TXT": {host: "example.i2labs.ca.", records: [["example"]], raw: "AACBgAABAAEAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAAAQAAHADAAQAAEAAAEsAAgHZXhhbXBsZQ"},
    "NAPTR": {
        host: "example.i2labs.ca.",
        records: [{
            flags: "US",
            order: 0,
            preference: 5,
            regexp: "",
            replacement: "example",
            service: "protocol=example"
        }],
        cmp: ["flags", "order", "preference", "regexp", "replacement", "service"],
        raw: "AACBgAABAAEAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAAAjAAHADAAjAAEAAAEsACIAAAAFAlVTEHByb3RvY29sPWV4YW1wbGUAB2V4YW1wbGUA"
    },
} as unknown as Record<keyof typeof RecordType | 'ANY', Expected>;

export const extendedTypes = {
    "DNSKEY": {
        host: "cloudflare.com",
        records: [
            {"zone_key": 1, "protocol": 3, "algorithm": 13, },
            {"zone_key": 1, "protocol": 3, "algorithm": 13, },
        ],
        cmp: ['zone_key', 'protocol', 'algorithm'],
        options: {dnssec: true},
        raw: "AACBgAABAAIAAAAACmNsb3VkZmxhcmUDY29tAAAwAAHADAAwAAEAAArjAEQBAAMNoJMRESz5E4gYzS_q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSMAMADAAAQAACuMARAEBAw2Z2yzBTKvcM9bXfaY6LxX3ERJYTyNOjR3EKOOeikqX4aonGlVdyQcB4X4qTEtvEgt8MtRPSsAr2JTPLUvnd4oZ"
    },
    "DS": {
        host: "cloudflare.com",
        records: [
            {"key_tag": 2371, "algorithm": 13, "digest_type": 2, },
        ],
        cmp: ["key_tag", "algorithm", "digest_type"],
        raw: "AACBgAABAAEAAAAACmNsb3VkZmxhcmUDY29tAAArAAHADAArAAEAAVGAACQJQw0CMploOabYCK_j60p5Wg5qejmnb8Uv8iiyK3b21jgm8rk"
    },
    "NSEC": {
        host: "cloudflare.com",
        records: [
            {"next_domain_name": ["\u0000","cloudflare","com",""], "type_bit_map": new Set([RecordType.A, RecordType.NS, RecordType.SOA, RecordType.HINFO, RecordType.MX, RecordType.TXT, RecordType.AAAA, RecordType.LOC, RecordType.SRV, RecordType.NAPTR, RecordType.CERT, RecordType.SSHFP, RecordType.RRSIG, RecordType.NSEC, RecordType.DNSKEY, RecordType.TLSA, RecordType.SMIMEA, RecordType.HIP, RecordType.CDS, RecordType.CDNSKEY, RecordType.OPENPGPKEY, RecordType.SVCB, RecordType.HTTPSSVC, RecordType.URI, RecordType.CAA]) },
        ],
        cmp: ["next_domain_name", "type_bit_map"],
        options: {dnssec: true},
        raw: "AACBgAABAAEAAAAACmNsb3VkZmxhcmUDY29tAAAvAAHADAAvAAEAAAEsACABAApjbG91ZGZsYXJlA2NvbQAACWIFgAxUC40cwAEBwA"
    },
    "LOC": {host: "example.i2labs.ca.", records: [
            {
                "VERSION": 0,
                "SIZE": 4000000,
                "HORIZ_PRE": 20000,
                "VERT_PRE": 0,
                "LATITUDE": 2147484648,
                "LONGITUDE": 2136682648,
                "ALTITUDE": 9999900,
                "size": 40000,
                "horiz_pre": 200,
                "vert_pre": 0,
                "latitude": {
                    "d": 0,
                    "m": 0,
                    "s": 1,
                    "ns": "S"
                },
                "longitude": {
                    "d": 3,
                    "m": 0,
                    "s": 1,
                    "ew": "W"
                },
                "altitude": -1
            }
        ],
        raw: "AACBgAABAAEAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAAAdAAHADAAdAAEAAAEsABAAIxIAgAAD6H9bMJgAmJYc"
    },
    "SPF": {host: "example.i2labs.ca.", records: ["v=spf1"], raw: "AACBgAABAAEAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAABjAAHADABjAAEAAAEsAAcGdj1zcGYx"},
    "SVCB": {host: "example.i2labs.ca.", records: [
            {
                "priority": 1,
                "domainname": [
                    "example",
                    "org",
                    ""
                ],
                "values": {
                    "alpn": ["h3", "h2"]
                }
            },
            {
                "priority": 2,
                "domainname": [
                    "https://foo",
                    "bar/baz",
                    ""
                ],
                "values": {}
            }
        ],
        raw: "AACBgAABAAIAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAABAAAHADABAAAEAAAEsABkAAQdleGFtcGxlA29yZwAAAQAGAmgzAmgywAwAQAABAAABLAAXAAILaHR0cHM6Ly9mb28HYmFyL2JhegA"
    },
    "URI": {host: "example.i2labs.ca.", records: [{
            "priority": 0,
            "weight": 0,
            "target": "example"
        }],
        raw: "AACBgAABAAEAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAAEAAAHADAEAAAEAAAEsAAsAAAAAZXhhbXBsZQ"
    },
    "SSHFP": {host: "example.i2labs.ca.", records: ["0 0 EXAMPLE"], pending: true},
    "SMIMEA": {host: "example.i2labs.ca.", records: ["0 0 0 example"], pending: true},
    "TLSA": {host: "example.i2labs.ca.", records: ["0 0 0 example"], pending: true},
    "HTTPS": {host: "example.i2labs.ca.", records: ["0 example.i2labs.ca."], pending: true},
} as unknown as Record<keyof typeof RecordType | 'ANY', Expected>;

export default {
    ...nodeTypes,
    ...extendedTypes,
}