export default {
    "SOA":{host:"i2labs.ca.", records:[{expire: 604800, hostmaster: "dns.cloudflare.com.", minttl: 3600, nsname: "isla.ns.cloudflare.com.", refresh: 10000, retry: 2400, serial: 2036371151}], cmp:["nsname","hostmaster","refresh","minttl","expire","retry"]},
    "A":{host:"example.i2labs.ca.", records:["0.0.0.0"]},
    "AAAA":{host:"example.i2labs.ca.", records:["::"]},
    "CNAME":{host:"cname.example.i2labs.ca.", records:["example.i2labs.ca."]},
    "CAA":{host:"cname.example.i2labs.ca.", records:["\\# 18 00 05 69 73 73 75 65 65 78 61 6d 70 6c 65 2e 6f 72 67"]}, // TODO {critical: 0, issue: "example.org"}], cmp:["critical","issue"]},
    "DNSKEY":{host:"cloudflare.com", records:["256 3 ECDSAP256SHA256 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==", "257 3 ECDSAP256SHA256 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="]},
    "DS":{host:"cloudflare.com", records:["2371 ECDSAP256SHA256 2 32996839a6d808afe3eb4a795a0e6a7a39a76fc52ff228b22b76f6d63826f2b9"]},
    "NS":{host:"cloudflare.com", records:["ns3.cloudflare.com.", "ns4.cloudflare.com.", "ns5.cloudflare.com.", "ns6.cloudflare.com.", "ns7.cloudflare.com."]},
    "SRV":{host:"_example._tcp.example.i2labs.ca.", records:[{priority: 0, weight: 0, port: 0, name: "example.org"}], cmp:["priority","weight","port","name"]},
    "LOC":{host:"example.i2labs.ca.", records:["\\# 16 00 00 00 00 80 00 00 00 80 00 00 00 00 98 96 80"]},
    "MX":{host:"example.i2labs.ca.", records:[{ priority: 0, exchange: "example.org."}], cmp:["priority","exchange"]},
    "PTR":{host:"example.i2labs.ca.", records:["example.org."]},
    "SPF":{host:"example.i2labs.ca.", records:["\\# 7 06 76 3d 73 70 66 31"]}, // TODO "\"v=spf1\""]},
    "SVCB":{host:"example.i2labs.ca.", records:["\\# 15 00 00 07 65 78 61 6d 70 6c 65 03 6f 72 67 00"]}, // TODO 0 example.org."]},
    "TXT":{host:"example.i2labs.ca.", records:[["\"example\""]]},
    "URI":{host:"example.i2labs.ca.", records:["\\# 11 00 00 00 00 65 78 61 6d 70 6c 65"]}, // TODO "0 0 \"example\""]}
    "NAPTR":{host:"example.i2labs.ca.", records:["\\# 33 00 00 00 00 01 55 10 70 72 6f 74 6f 63 6f 6c 3d 65 78 61 6d 70 6c 65 00 07 65 78 61 6d 70 6c 65 00"]}, // TODO {flags: "\#", order: 0, preference: 0, regexp: 0, replacement: 0, service: 33}], cmp:["flags","order","preference","regexp","replacement","service"]},
    "SSHFP":{host:"example.i2labs.ca.", records:["0 0 EXAMPLE"], pending: true},
    "SMIMEA":{host:"example.i2labs.ca.", records:["0 0 0 example"], pending: true},
    "TLSA":{host:"example.i2labs.ca.", records:["0 0 0 example"], pending: true},
    "HTTPS":{host:"example.i2labs.ca.", records:["0 example.i2labs.ca."], pending: true},
} as {[key: string]: {host: string, records: any[], cmp?: string[], pending?: boolean}}
