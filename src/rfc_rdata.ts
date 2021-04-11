import {RecordType} from "./constants.js";
import {Tokenizer, TokenType} from "./rfc1035.js";

type IP4ADDR = [number, number, number, number];
type IP6ADDR = [number, number, number, number, number, number, number, number];

function IP4ADDR(d: Tokenizer): IP4ADDR {return (new Array(4)).fill(undefined).map(x=>Number(d.next('u8').value)) as IP4ADDR;}
function IP6ADDR(d: Tokenizer): IP6ADDR {return (new Array(8)).fill(undefined).map(x=>Number(d.next('u16').value)) as IP6ADDR;}
function EXP(d: Tokenizer): number {return d.next('u4').value as number * Math.pow(10, d.next('u4').value as number);}

type OPAQUE = ArrayBuffer;
type DOMAINNAME = string[];
const DOMAINNAME = 'string[]';


type _RRDataLayout = ((d: Tokenizer)=>any)|TokenType[]|TokenType;
type RRDataLayout = _RRDataLayout|{[key: string]: _RRDataLayout};

const rdata = new Map<RecordType, RRDataLayout>();
rdata.set(RecordType.A, IP4ADDR);
rdata.set(RecordType.NS, DOMAINNAME);
rdata.set(RecordType.MD, DOMAINNAME);
rdata.set(RecordType.MF, DOMAINNAME);
rdata.set(RecordType.CNAME, DOMAINNAME);
rdata.set(RecordType.SOA, {MNAME: DOMAINNAME, RNAME: DOMAINNAME, SERIAL: 'u32', REFRESH: 'u32', RETRY: 'u32', EXPIRE: 'u32', MINIMUM: 'u32'});
rdata.set(RecordType.MB, DOMAINNAME);
rdata.set(RecordType.MG, DOMAINNAME);
rdata.set(RecordType.MR, DOMAINNAME);
rdata.set(RecordType.NULL, 'string[*]');
rdata.set(RecordType.WKS, {ADDRESS: IP4ADDR, PROTOCOL: 'u8', BITMAP: 'opaque'});
rdata.set(RecordType.PTR, DOMAINNAME);
rdata.set(RecordType.HINFO, {CPU: 'string', OS: 'string'});
rdata.set(RecordType.MINFO, {RMAILBX: DOMAINNAME, EMAILBX: DOMAINNAME});
rdata.set(RecordType.MX, {PREFERENCE: 's16', EXCHANGE: DOMAINNAME});
rdata.set(RecordType.TXT, 'string[]');
rdata.set(RecordType.RP, {mbox: DOMAINNAME, txt: DOMAINNAME});
rdata.set(RecordType.AFSDB, {subtype: 's16', hostname: DOMAINNAME});
rdata.set(RecordType.X25, 'string');
rdata.set(RecordType.ISDN, (d: Tokenizer): {address: string, sa?: string}=>{const v: {address: string, sa?: string}={address: d.next('string').value as string, sa: undefined}; const n = d.next(); v.sa = n.done ? undefined : n.value as string; return v;});
rdata.set(RecordType.RT, {preference: 's16', 'intermediate-host': DOMAINNAME});
rdata.set(RecordType.NSAP, 'string');
rdata.set(RecordType['NSAP-PTR'], 'string');
rdata.set(RecordType.SIG, {type_covered: 'u16', algorithm: 'u8', labels: 'u8', original_ttl: 'u32', sig_expiration: 'u32', sig_inception: 'u32', key_tag: 'u16', signer: DOMAINNAME, signature: 'opaque'});
rdata.set(RecordType.KEY, {flags: 'u16', protocol: 'u8', algorithm: 'u8', public_key: 'opaque'});
rdata.set(RecordType.PX, {PREFERENCE: 's16', MAP822: DOMAINNAME, MAPX400: DOMAINNAME});
rdata.set(RecordType.GPOS, {LONGITUDE: 'string', LATITUDE: 'string', ALTITUDE: 'string'});
rdata.set(RecordType.AAAA, IP6ADDR);
rdata.set(RecordType.LOC, (d: Tokenizer)=>{
    const val = parseToken(d, {VERSION: 'u8', SIZE: EXP, HORIZ_PRE: EXP, VERT_PRE: EXP, LATITUDE: 'u32', LONGITUDE: 'u32', ALTITUDE: 'u32'});
    const dms = (n: number)=>({d: Math.abs(Math.trunc(n / 3600000)), m: Math.abs(Math.trunc((n % 3600000) / 60000)), s: Math.abs(((n % 3600000) % 60000) / 1000)});
    val.size = val.SIZE / 100;
    val.horiz_pre = val.HORIZ_PRE / 100;
    val.vert_pre = val.VERT_PRE / 100;
    val.latitude = dms(val.LATITUDE - 2**31);
    val.latitude.ns = val.LATITUDE <= 0 ? "N" : "S";
    val.longitude = dms(val.LONGITUDE - 2**31);
    val.longitude.ew = val.LONGITUDE <= 0 ? "E" : "W";
    val.altitude = val.ALTITUDE / 100 - 100000;
    return val;
});
rdata.set(RecordType.NXT, {next_domain_name: DOMAINNAME, type_bit_map: 'opaque'});
rdata.set(RecordType.EID, 'opaque');
rdata.set(RecordType.NIMLOC, 'opaque');
rdata.set(RecordType.SRV, {priority: 'u16', weight: 'u16', port: 'u16', target: DOMAINNAME});
rdata.set(RecordType.ATMA, 'opaque');
rdata.set(RecordType.NAPTR, {ORDER: 'u16', PREFERENCE: 'u16', FLAGS: 'string', SERVICES: 'string', REGEXP: 'string', REPLACEMENT: DOMAINNAME});
rdata.set(RecordType.KX, {PREFERENCE: 'u16', EXCHANGER: DOMAINNAME});
rdata.set(RecordType.CERT, {type: 'u16', key_tag: 'u16', algorithm: 'u8', certificate: 'opaque'});
rdata.set(RecordType.A6, 'opaque');
rdata.set(RecordType.DNAME, DOMAINNAME);
rdata.set(RecordType.SINK, {coding: 'u8', subcoding: 'u8', data: 'opaque'});
rdata.set(RecordType.OPT, {code: 'u16', length: 'u16', data: 'opaque'});
rdata.set(RecordType.APL, {ADDRESSFAMILY: 'u16', PREFIX: 'u8', N: 'bit', AFDLENGTH: (d: Tokenizer): number=>(new Array(7)).fill(undefined).map(x=>d.next('bit').value as number).reduce((acc: number, cur: number)=>((acc<<1)+cur), 0), AFDPART: 'opaque'});
rdata.set(RecordType.DS, {key_tag: 'u16', algorithm: 'u8', digest_type: 'u8', digest: 'opaque'});
rdata.set(RecordType.SSHFP, {algorithm: 'u8', fp_type: 'u8', fingerprint: 'opaque'});
rdata.set(RecordType.IPSECKEY, (d: Tokenizer)=>{
    const v={precedence: d.next('u8').value, gateway_type: d.next('u8').value, algorithm: d.next('u8').value} as {precedence: number, gateway_type: number, algorithm: number, gateway?: IP4ADDR|IP6ADDR|DOMAINNAME, public_key: OPAQUE};
    switch (v.gateway_type) {
        case 1:
            v.gateway = IP4ADDR(d);
            break;
        case 2:
            v.gateway = IP6ADDR(d);
            break;
        case 3:
            v.gateway = d.next(DOMAINNAME).value as DOMAINNAME;
            break;
    }
    v.public_key = d.next('opaque').value as OPAQUE;
    return v;
});
rdata.set(RecordType.RRSIG, rdata.get(RecordType.SIG));
rdata.set(RecordType.NSEC, rdata.get(RecordType.NXT));
rdata.set(RecordType.DNSKEY, rdata.get(RecordType.KEY));
rdata.set(RecordType.DHCID, 'opaque');
rdata.set(RecordType.NSEC3, {hash_algorithm: 'u8', flags: 'u8', iterations: 'u16', salt: 'string', next_hashed_owner_name: 'string', type_bit_map: 'opaque'});
rdata.set(RecordType.NSEC3PARAM, {hash_algorithm: 'u8', flags: 'u8', iterations: 'u16', salt: 'string'});
rdata.set(RecordType.TLSA, {cert_usage: 'u8', selector: 'u8', matching_type: 'u8', cert_assoc_data: 'opaque'});
rdata.set(RecordType.SMIMEA, rdata.get(RecordType.TLSA));
rdata.set(RecordType.HIP, 'opaque');
rdata.set(RecordType.NINFO, 'opaque');
rdata.set(RecordType.RKEY, 'opaque');
rdata.set(RecordType.TALINK, 'opaque');
rdata.set(RecordType.CDS, rdata.get(RecordType.DS));
rdata.set(RecordType.CDNSKEY, rdata.get(RecordType.DNSKEY));
rdata.set(RecordType.OPENPGPKEY, 'opaque');
rdata.set(RecordType.CSYNC, {SOA_serial: 'u32', flags: 'u16', type_bit_map: 'opaque'});
rdata.set(RecordType.ZONEMD, 'opaque');
rdata.set(RecordType.SVCB, {priority: 'u16', domainname: DOMAINNAME, values: (d: Tokenizer)=>{
    const vals = {} as Record<string, string[]>;
    for (let next = d.next('u16'); !next.done; next = d.next('u16')) {
        const key = next.value as number;
        let len = d.next('u16').value as number;
        const val: string[] = [];
        while (len > 0) {
            const v = d.next('string').value as string;
            len -= v.length + 1;
            val.push(v);
        }
        // const val = d.next(`string[${len}]`).value as string;
        switch (key) {
            case 1:
                vals.alpn = val;
                break;
            case 2:
                vals.port = val;
                break;
            case 3:
                vals.esnikeys = val;
                break;
            case 4:
                vals.ipv4hint = val;
                break;
            case 6:
                vals.ipv6hint = val;
                break;
            default:
            case 0:
            case 5:
                vals[`key${key}`] = val;
                break;
        }
    }
    return vals;
}});
rdata.set(RecordType.HTTPSSVC, rdata.get(RecordType.SVCB));
rdata.set(RecordType.SPF, 'string[]');
rdata.set(RecordType.UINFO, 'opaque');
rdata.set(RecordType.UID, 'opaque');
rdata.set(RecordType.GID, 'opaque');
rdata.set(RecordType.UNSPEC, 'opaque');
rdata.set(RecordType.NID, 'opaque');
rdata.set(RecordType.L32, 'opaque');
rdata.set(RecordType.L64, 'opaque');
rdata.set(RecordType.LP, 'opaque');
rdata.set(RecordType.EUI48, (d: Tokenizer)=>(new Array(6)).fill(undefined).map(x=>d.next('u8').value as number));
rdata.set(RecordType.EUI64, 'opaque');
rdata.set(RecordType.TSIG, {algorithm_name: DOMAINNAME, time_signed_upper: 'u16', time_signed: 'u32', fudge: 'u16', MAC: (d: Tokenizer)=>(new Array(d.next('u16').value as number)).fill(undefined).map(x=>d.next('u8').value as number), original_id: 'u16', error: 'u16', other_len: 'u16', other_data: 'opaque'});
// Not RR types
// rdata.set(RecordType.IXFR, 'opaque');
// rdata.set(RecordType.AXFR, 'opaque');
// rdata.set(RecordType.MAILB, 'opaque');
// rdata.set(RecordType.MAILA, 'opaque');
// rdata.set(RecordType['*'], 'opaque');
rdata.set(RecordType.URI, {priority: 'u16', weight: 'u16', target: 'string[*]'});
rdata.set(RecordType.CAA, {flags: 'u8', tag: 'string', value: 'string[*]'});
rdata.set(RecordType.AVC, 'opaque');
rdata.set(RecordType.DOA, 'opaque');
rdata.set(RecordType.AMTRELAY, 'opaque');
rdata.set(RecordType.TA, 'opaque');
rdata.set(RecordType.DLV, 'opaque');

function parseToken(d: Tokenizer, layout: RRDataLayout): any {
    switch (typeof layout) {
        case "function":
            return layout(d);
        case "object":
            return Object.entries(layout).reduce((acc, [k, v])=>{acc[k] = parseToken(d, v); return acc;}, {} as {[key: string]: any});
        case "string":
            return d.next(layout).value;
    }
}

export default function parse(d: Tokenizer, type: RecordType.A): IP4ADDR;
export default function parse(d: Tokenizer, type: RecordType.AAAA): IP6ADDR;
export default function parse(d: Tokenizer, type: RecordType.SOA): {MNAME: string[], RNAME: string[], SERIAL: number, REFRESH: number, RETRY: number, EXPIRE: number, MINIMUM: number};
export default function parse(d: Tokenizer, type: RecordType.NS|RecordType.MD|RecordType.MF|RecordType.CNAME|RecordType.SOA|RecordType.MB|RecordType.MG|RecordType.MR|RecordType.PTR|RecordType.TXT|RecordType.DNAME|RecordType.SPF): string[];
export default function parse(d: Tokenizer, type: RecordType.NULL|RecordType.X25|RecordType.NSAP): string;
export default function parse(d: Tokenizer, type: RecordType.WKS): {ADDRESS: IP4ADDR, PROTOCOL: number, BITMAP: OPAQUE};
export default function parse(d: Tokenizer, type: RecordType.HINFO): {CPU: string, OS: string};
export default function parse(d: Tokenizer, type: RecordType.MINFO): {RMAILBX: DOMAINNAME, EMAILBX: DOMAINNAME};
export default function parse(d: Tokenizer, type: RecordType.MX): {PREFERENCE: string, EXCHANGE: DOMAINNAME};
export default function parse(d: Tokenizer, type: RecordType.RP): {mbox: DOMAINNAME, txt: DOMAINNAME};
export default function parse(d: Tokenizer, type: RecordType.AFSDB): {subtype: string, hostname: DOMAINNAME};
export default function parse(d: Tokenizer, type: RecordType.ISDN): {address: string, sa?: string};
export default function parse(d: Tokenizer, type: RecordType.RT): {preference: string, 'intermediate-host': DOMAINNAME};
export default function parse(d: Tokenizer, type: RecordType.SIG|RecordType.RRSIG): {type_covered: number, algorithm: number, labels: number, original_ttl: number, sig_expiration: number, sig_inception: number, key_tag: number, signer: DOMAINNAME, signature: OPAQUE};
export default function parse(d: Tokenizer, type: RecordType.KEY|RecordType.DNSKEY|RecordType.CDNSKEY): {flags: number, protocol: number, algorithm: number, public_key: OPAQUE};
export default function parse(d: Tokenizer, type: RecordType.PX): {PREFERENCE: number, MAP822: DOMAINNAME, MAPX400: DOMAINNAME};
export default function parse(d: Tokenizer, type: RecordType.GPOS): {LONGITUDE: string, LATITUDE: string, ALTITUDE: string};
export default function parse(d: Tokenizer, type: RecordType.LOC): {VERSION: number, SIZE: number, HORIZ_PRE: number, VERT_PRE: number, LATITUDE: number, LONGITUDE: number, ALTITUDE: number, size: number, horiz_pre: number, vert_pre: number, latitude: {d: number, m: number, s: number, ns: string}, longitude: {d: number, m: number, s: number, ew: string}, altitude: number};
export default function parse(d: Tokenizer, type: RecordType.NXT|RecordType.NSEC): {next_domain_name: DOMAINNAME, type_bit_map: OPAQUE};
export default function parse(d: Tokenizer, type: RecordType.EID|RecordType.NIMLOC|RecordType.ATMA|RecordType.A6|RecordType.DHCID|RecordType.HIP|RecordType.NINFO|RecordType.RKEY|RecordType.TALINK|RecordType.OPENPGPKEY|RecordType.ZONEMD|RecordType.UINFO|RecordType.UID|RecordType.GID|RecordType.UNSPEC|RecordType.NID|RecordType.L32|RecordType.L64|RecordType.LP|RecordType.EUI64|RecordType.AVC|RecordType.DOA|RecordType.AMTRELAY|RecordType.TA|RecordType.DLV): OPAQUE;
export default function parse(d: Tokenizer, type: RecordType.SRV): {priority: number, weight: number, port: number, target: DOMAINNAME};
export default function parse(d: Tokenizer, type: RecordType.NAPTR): {ORDER: number, PREFERENCE: number, FLAGS: string, SERVICES: string, REGEXP: string, REPLACEMENT: DOMAINNAME};
export default function parse(d: Tokenizer, type: RecordType.KX): {PREFERENCE: number, EXCHANGER: DOMAINNAME};
export default function parse(d: Tokenizer, type: RecordType.CERT): {type: number, key_tag: number, algorithm: number, certificate: OPAQUE};
export default function parse(d: Tokenizer, type: RecordType.SINK): {coding: number, subcoding: number, data: OPAQUE};
export default function parse(d: Tokenizer, type: RecordType.OPT): {code: number, length: number, data: OPAQUE};
export default function parse(d: Tokenizer, type: RecordType.APL): {ADDRESSFAMILY: number, PREFIX: number, N: number, AFDLENGTH: number, AFDPART: OPAQUE};
export default function parse(d: Tokenizer, type: RecordType.DS|RecordType.CDS): {key_tag: number, algorithm: number, digest_type: number, digest: OPAQUE};
export default function parse(d: Tokenizer, type: RecordType.SSHFP): {algorithm: number, fp_type: number, fingerprint: OPAQUE};
export default function parse(d: Tokenizer, type: RecordType.IPSECKEY): {precedence: number, gateway_type: number, algorithm: number, gateway?: IP4ADDR|IP6ADDR|DOMAINNAME, public_key: OPAQUE};
export default function parse(d: Tokenizer, type: RecordType.NSEC3): {hash_algorithm: number, flags: number, iterations: number, salt: string, next_hashed_owner_name: string, type_bit_map: OPAQUE};
export default function parse(d: Tokenizer, type: RecordType.NSEC3PARAM): {hash_algorithm: number, flags: number, iterations: number, salt: string};
export default function parse(d: Tokenizer, type: RecordType.TLSA|RecordType.SMIMEA): {cert_usage: number, selector: number, matching_type: number, cert_assoc_data: OPAQUE};
export default function parse(d: Tokenizer, type: RecordType.CSYNC): {SOA_serial: number, flags: number, type_bit_map: OPAQUE};
export default function parse(d: Tokenizer, type: RecordType.SVCB|RecordType.HTTPSSVC): {priority: number, domainname: DOMAINNAME, values: Record<'alpn'|'port'|'esnikeys'|'ipv4hint'|'ipv6hint'|string, string[]>};
export default function parse(d: Tokenizer, type: RecordType.EUI48): [number, number, number, number, number, number];
export default function parse(d: Tokenizer, type: RecordType.TSIG): {algorithm_name: DOMAINNAME, time_signed_upper: number, time_signed: number, fudge: number, MAC: number[], original_id: number, error: number, other_len: number, other_data: OPAQUE};
export default function parse(d: Tokenizer, type: RecordType.URI): {priority: number, weight: number, target: string};
export default function parse(d: Tokenizer, type: RecordType.CAA): {flags: number, tag: string, value: string};
export default function parse(d: Tokenizer, type: RecordType): any;
export default function parse(d: Tokenizer, type: RecordType): any {
    return parseToken(d, rdata.get(type) || 'opaque');
}
