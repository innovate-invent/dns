import {RecordType} from "../src/constants";

export type Expected = {host: string, records: any[], cmp?: string[], pending?: boolean};

export const nodeTypes = { // The expected values here should be identical to what NodeJS DNS returns
    "SOA": {
        host: "i2labs.ca.",
        records: [{
            expire: 604800,
            hostmaster: "dns.cloudflare.com",
            minttl: 3600,
            nsname: "isla.ns.cloudflare.com",
            refresh: 10000,
            retry: 2400,
            serial: 2036371151
        }],
        cmp: ["nsname", "hostmaster", "refresh", "minttl", "expire", "retry"]
    },
    "A": {host: "example.i2labs.ca.", records: ["0.0.0.0"]},
    "AAAA": {host: "example.i2labs.ca.", records: ["2001:db8:85a3::8a2e:370:7334", "::"]},
    "CNAME": {host: "cname.example.i2labs.ca.", records: ["example.i2labs.ca"]},
    "CAA": {
        host: "cname.example.i2labs.ca.",
        records: [{critical: 0, issue: "example.org"}],
        cmp: ["critical", "issue"]
    },
    "MX": {
        host: "example.i2labs.ca.",
        records: [{priority: 0, exchange: "example.org"}],
        cmp: ["priority", "exchange"]
    },
    "NS": {
        host: "cloudflare.com",
        records: ["ns3.cloudflare.com", "ns4.cloudflare.com", "ns5.cloudflare.com", "ns6.cloudflare.com", "ns7.cloudflare.com"]
    },
    "SRV": {
        host: "_example._tcp.example.i2labs.ca.",
        records: [{priority: 0, weight: 0, port: 0, name: "example.org"}],
        cmp: ["priority", "weight", "port", "name"]
    },
    "PTR": {host: "example.i2labs.ca.", records: ["example.org"]},
    "TXT": {host: "example.i2labs.ca.", records: [["example"]]},
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
        cmp: ["flags", "order", "preference", "regexp", "replacement", "service"]
    },
} as unknown as Record<keyof typeof RecordType | 'ANY', Expected>;

export const extendedTypes = {
    "DNSKEY": {
        host: "cloudflare.com",
        records: [
            {"flags": 256, "protocol": 3, "algorithm": 13, },
            {"flags": 257, "protocol": 3, "algorithm": 13, },
        ],
        cmp: ['flags', 'protocol', 'algorithm'],
    },
    "DS": {
        host: "cloudflare.com",
        records: [
            {"key_tag": 2371, "algorithm": 13, "digest_type": 2, },
        ],
        cmp: ["key_tag", "algorithm", "digest_type"]
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
        ]
    },
    "SPF": {host: "example.i2labs.ca.", records: ["v=spf1"]},
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
        ]
    },
    "URI": {host: "example.i2labs.ca.", records: [{
            "priority": 0,
            "weight": 0,
            "target": "example"
        }]
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
