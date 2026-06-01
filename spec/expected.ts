/**
 * Various DNS record type queries and their expected parsed response values for use in the test suite
 */

import {RecordType} from "../src/constants.js";
import {ResolveOptions} from "../src/dns.js";
import {OPAQUE} from "../src/rfc_rdata.js";

export type Expected = {host: string, records: any[], cmp?: string[], pending?: boolean, options?: ResolveOptions, raw?: string};

//import data from "../testdata/data.json"

// 'raw' values are the base64url encoded response body for each request fetched from the test DNS records hosted on Cloudflare.
// This to prevent test failures as Cloudflare seems to be dropping support for some record types.

/*
 example.xa.	1	IN	A	0.0.0.0
 example.xa.	1	IN	AAAA	2001:db8:85a3::8a2e:370:7334
 example.xa.	1	IN	AAAA	::
 example.xa.	1	IN	CAA	0 issue "example.org"
 cname.example.xa.	1	IN	CNAME	example.xa.
 example.xa.	1	IN	HTTPS	0 example.xa.
 example.xa.	1	IN	LOC	00 00 1.000 N 03 00 1.000 W -1m 20m 1m 0.00m
 example.xa.	1	IN	MX	0 example.org.
 example.xa.	1	IN	NAPTR	0 5 "US" "protocol=example" "" example.
 example.xa.	1	IN	PTR	example.org.
 example.xa.	1	IN	SMIMEA	0 0 0 436c6f7564666c
 example.xa.	1	IN	SPF	"v=spf1"
 _example._tcp.example.xa.	1	IN	SRV	0 0 0 example.org.
 example.xa.	1	IN	SSHFP	0 0 436C6F7564666C
 example.xa.	1	IN	SVCB	2 https://foo.bar/baz.
 example.xa.	1	IN	SVCB	1 example.org. alpn="h3,h2"
 example.xa.	1	IN	TLSA	0 0 0 436c6f7564666c
 example.xa.	1	IN	TXT	"example"
 *.foo.example.xa.	1	IN	TXT	"test"
 example.xa.	1	IN	URI	0 0 "example"
 */

// TODO error codes
export const nodeTypes = { // The expected values here should be identical to what NodeJS DNS returns
    "SOA": {
        host: "example.xa.",
        records: [{
            expire: 604800,
            hostmaster: "dns.example.xa",
            minttl: 1800,
            nsname: "isla.ns.example.xa",
            refresh: 10000,
            retry: 2400,
            serial: 2036371151
        }],
        cmp: ["nsname", "hostmaster", "refresh", "minttl", "expire", "retry"],
        raw: "AACBgAABAAEAAAAABmkybGFicwJjYQAABgABwAwABgABAAAHCAAyBGlzbGECbnMKY2xvdWRmbGFyZQNjb20AA2Ruc8AvjRwMhAAAJxAAAAlgAAk6gAAABwg",
    },
    "A": {host: "example.xa.", records: ["0.0.0.0"], raw: "AACBgAABAAEAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAAABAAHADAABAAEAAAEsAAQAAAAA"},
    "AAAA": {host: "example.xa.", records: ["2001:db8:85a3::8a2e:370:7334", "::"], raw: "AACBgAABAAIAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAAAcAAHADAAcAAEAAAEsABAAAAAAAAAAAAAAAAAAAAAAwAwAHAABAAABLAAQIAENuIWjAAAAAIouA3BzNA"},
    "CNAME": {host: "cname.example.xa.", records: ["example.xa"], raw: "AACBgAABAAEAAAAABWNuYW1lB2V4YW1wbGUGaTJsYWJzAmNhAAAFAAHADAAFAAEAAAEsAALAEg"},
    "CAA": {
        host: "cname.example.xa.",
        records: [{critical: 0, issue: "example.org"}],
        cmp: ["critical", "issue"],
        raw: "AACBgAABAAIAAAAABWNuYW1lB2V4YW1wbGUGaTJsYWJzAmNhAAEBAAHADAAFAAEAAAEsAALAEsASAQEAAQAAASwAEgAFaXNzdWVleGFtcGxlLm9yZw"
    },
    "MX": {
        host: "example.xa.",
        records: [{priority: 0, exchange: "example.org"}],
        cmp: ["priority", "exchange"],
        raw: "AACBgAABAAEAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAAAPAAHADAAPAAEAAAEsAA8AAAdleGFtcGxlA29yZwA"
    },
    "NS": {
        host: "example.xa",
        records: ["ns3.example.xa", "ns4.example.xa", "ns5.example.xa", "ns6.example.xa", "ns7.example.xa"],
        raw: "AACBgAABAAUAAAAACmNsb3VkZmxhcmUDY29tAAACAAHADAACAAEAAVGAAAYDbnMzwAzADAACAAEAAVGAAAYDbnM0wAzADAACAAEAAVGAAAYDbnM1wAzADAACAAEAAVGAAAYDbnM2wAzADAACAAEAAVGAAAYDbnM3wAw"
    },
    "SRV": {
        host: "_example._tcp.example.xa.",
        records: [{priority: 0, weight: 0, port: 0, name: "example.org"}],
        cmp: ["priority", "weight", "port", "name"],
        raw: "AACBgAABAAEAAAAACF9leGFtcGxlBF90Y3AHZXhhbXBsZQZpMmxhYnMCY2EAACEAAcAMACEAAQAAASwAEwAAAAAAAAdleGFtcGxlA29yZwA"
    },
    "PTR": {host: "example.xa.", records: ["example.org"], raw: "AACBgAABAAEAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAAAMAAHADAAMAAEAAAEsAA0HZXhhbXBsZQNvcmcA"},
    "TXT": {host: "example.xa.", records: [["example"]], raw: "AACBgAABAAEAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAAAQAAHADAAQAAEAAAEsAAgHZXhhbXBsZQ"},
    "NAPTR": {
        host: "example.xa.",
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
        "SOA": {
            host: "example.xa.",
            records: [{
                MNAME: ["ns1", "example", "xa", ""],
                RNAME: ["admin", ""],
                SERIAL: 2024041900,
                REFRESH: 21600,
                RETRY: 2400,
                EXPIRE: 604800,
                MINIMUM: 86400
            }],
            cmp: ["nsname", "hostmaster", "refresh", "minttl", "expire", "retry"],
            raw: "AACBgAABAAEAAAAABmkybGFicwJjYQAABgABwAwABgABAAAHCAAyBGlzbGECbnMKY2xvdWRmbGFyZQNjb20AA2Ruc8AvjRwMhAAAJxAAAAlgAAk6gAAABwg",
        },
        "A": {host: "example.xa.", records: [[0, 0, 0, 0]], raw: "AACBgAABAAEAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAAABAAHADAABAAEAAAEsAAQAAAAA"},
        "AAAA": {host: "example.xa.", records: [[8193, 3512, 34211, 0, 0, 35374, 880, 29492], [0, 0, 0, 0, 0, 0, 0, 0]], raw: "AACBgAABAAIAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAAAcAAHADAAcAAEAAAEsABAAAAAAAAAAAAAAAAAAAAAAwAwAHAABAAABLAAQIAENuIWjAAAAAIouA3BzNA"},
        "CNAME": {host: "cname.example.xa.", records: [["example", "xa", ""]], raw: "AACBgAABAAEAAAAABWNuYW1lB2V4YW1wbGUGaTJsYWJzAmNhAAAFAAHADAAFAAEAAAEsAALAEg"},
        "CAA": {
            host: "cname.example.xa.",
            records: [{issuer_critical: false, tag: "issue", value: ["example", "org", ""]}],
            cmp: ["critical", "issue"],
            raw: "AACBgAABAAIAAAAABWNuYW1lB2V4YW1wbGUGaTJsYWJzAmNhAAEBAAHADAAFAAEAAAEsAALAEsASAQEAAQAAASwAEgAFaXNzdWVleGFtcGxlLm9yZw"
        },
        "MX": {
            host: "example.xa.",
            records: [{PREFERENCE: 0, EXCHANGE: ["example", "org", ""]}],
            cmp: ["priority", "exchange"],
            raw: "AACBgAABAAEAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAAAPAAHADAAPAAEAAAEsAA8AAAdleGFtcGxlA29yZwA"
        },
        "NS": {
            host: "example.xa",
            records: [["ns3", "example", "xa", ""], ["ns4", "example", "xa", ""], ["ns5", "example", "xa", ""], ["ns6", "example", "xa", ""], ["ns7", "example", "xa", ""]],
            raw: "AACBgAABAAUAAAAACmNsb3VkZmxhcmUDY29tAAACAAHADAACAAEAAVGAAAYDbnMzwAzADAACAAEAAVGAAAYDbnM0wAzADAACAAEAAVGAAAYDbnM1wAzADAACAAEAAVGAAAYDbnM2wAzADAACAAEAAVGAAAYDbnM3wAw"
        },
        "SRV": {
            host: "_example._tcp.example.xa.",
            records: [{priority: 0, weight: 0, port: 0, target: ["example", "org", ""]}],
            cmp: ["priority", "weight", "port", "name"],
            raw: "AACBgAABAAEAAAAACF9leGFtcGxlBF90Y3AHZXhhbXBsZQZpMmxhYnMCY2EAACEAAcAMACEAAQAAASwAEwAAAAAAAAdleGFtcGxlA29yZwA"
        },
        "PTR": {host: "example.xa.", records: [["example", "org", ""]], raw: "AACBgAABAAEAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAAAMAAHADAAMAAEAAAEsAA0HZXhhbXBsZQNvcmcA"},
        "TXT": {host: "example.xa.", records: [["example", "text"]], raw: "AACBgAABAAEAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAAAQAAHADAAQAAEAAAEsAAgHZXhhbXBsZQ"},
        "NAPTR": {
            host: "example.xa.",
            records: [{
                FLAGS: "US",
                ORDER: 0,
                PREFERENCE: 5,
                REGEXP: "",
                REPLACEMENT: ["example", ""],
                SERVICES: "protocol=example"
            }],
            cmp: ["flags", "order", "preference", "regexp", "replacement", "service"],
            raw: "AACBgAABAAEAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAAAjAAHADAAjAAEAAAEsACIAAAAFAlVTEHByb3RvY29sPWV4YW1wbGUAB2V4YW1wbGUA"
        },
    "DNSKEY": {
        host: "example.xa",
        records: [
            {"zone_key": 1, "protocol": 3, "algorithm": 13, public_key: new Uint8Array([1,2,3,4]).buffer},
            {"zone_key": 1, "protocol": 3, "algorithm": 13, public_key: new Uint8Array([1,2,3,4]).buffer},
        ],
        cmp: ['zone_key', 'protocol', 'algorithm'],
        options: {dnssec: true},
        raw: "AACBgAABAAIAAAAACmNsb3VkZmxhcmUDY29tAAAwAAHADAAwAAEAAArjAEQBAAMNoJMRESz5E4gYzS_q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSMAMADAAAQAACuMARAEBAw2Z2yzBTKvcM9bXfaY6LxX3ERJYTyNOjR3EKOOeikqX4aonGlVdyQcB4X4qTEtvEgt8MtRPSsAr2JTPLUvnd4oZ"
    },
    "DS": {
        host: "example.xa",
        records: [
            {"key_tag": 2371, "algorithm": 13, "digest_type": 2, digest: new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20]).buffer },
        ],
        cmp: ["key_tag", "algorithm", "digest_type"],
        raw: "AACBgAABAAEAAAAACmNsb3VkZmxhcmUDY29tAAArAAHADAArAAEAAVGAACQJQw0CMploOabYCK_j60p5Wg5qejmnb8Uv8iiyK3b21jgm8rk"
    },
    "NSEC": {
        host: "example.xa",
        records: [
            {"next_domain_name": ["\u0000","example","xa",""], "type_bit_map": new Set([RecordType.A, RecordType.NS, RecordType.SOA, RecordType.HINFO, RecordType.MX, RecordType.TXT, RecordType.AAAA, RecordType.LOC, RecordType.SRV, RecordType.NAPTR, RecordType.CERT, RecordType.SSHFP, RecordType.RRSIG, RecordType.NSEC, RecordType.DNSKEY, RecordType.TLSA, RecordType.SMIMEA, RecordType.HIP, RecordType.CDS, RecordType.CDNSKEY, RecordType.OPENPGPKEY, RecordType.SVCB, /*RecordType.HTTPSSVC,*/ RecordType.URI, RecordType.CAA]) },
        ],
        cmp: ["next_domain_name", "type_bit_map"],
        options: {dnssec: true},
        raw: "AACBgAABAAEAAAAACmNsb3VkZmxhcmUDY29tAAAvAAHADAAvAAEAAAEsACABAApjbG91ZGZsYXJlA2NvbQAACWIFgAxUC40cwAEBwA"
    },
    "LOC": {host: "example.xa.", records: [
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
    "SPF": {host: "example.xa.", records: [["v=spf1"]], raw: "AACBgAABAAEAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAABjAAHADABjAAEAAAEsAAcGdj1zcGYx"},
    "SVCB": {host: "example.xa.", records: [
            {
                "priority": 1,
                "domainname": [
                    "example",
                    "xa",
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
    "URI": {host: "example.xa.", records: [{
            "priority": 0,
            "weight": 0,
            "target": "example"
        }],
        raw: "AACBgAABAAEAAAAAB2V4YW1wbGUGaTJsYWJzAmNhAAEAAAHADAEAAAEAAAEsAAsAAAAAZXhhbXBsZQ"
    },
    "SSHFP": {host: "example.xa.", records: [{algorithm: 0, fp_type: 0, fingerprint: new Uint8Array([1, 2, 3, 4]).buffer}], pending: true},
    "SMIMEA": {host: "example.xa.", records: [{
            cert_usage: 0,
            selector: 0,
            matching_type: 0,
            cert_assoc_data: new Uint8Array([1, 2, 3, 4]).buffer
        }], pending: true},
    "TLSA": {host: "example.xa.", records: [{
            cert_usage: 0,
            selector: 0,
            matching_type: 0,
            cert_assoc_data: new Uint8Array([1, 2, 3, 4]).buffer
        }], pending: true},
    //"HTTPS": {host: "example.xa.", records: ["0 example.xa."], pending: true},
} as unknown as Record<keyof typeof RecordType, Expected>;

export default {
    ...nodeTypes,
    ...extendedTypes,
}