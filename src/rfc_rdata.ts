import {RecordType} from "./constants.js";
import {Tokenizer, TokenType} from "./rfc1035.js";

function IP4ADDR(d: Tokenizer): number[] {return (new Array(4)).fill(undefined).map(x=>Number(d.next('u8').value));}
function IP6ADDR(d: Tokenizer): number[] {return (new Array(8)).fill(undefined).map(x=>Number(d.next('u16').value));}
function EXP(d: Tokenizer): number {return d.next('u4').value as number * Math.pow(10, d.next('u4').value as number);}

const DOMAINNAME = 'string[]'

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
    const v={precedence: d.next('u8').value, gateway_type: d.next('u8').value, algorithm: d.next('u8').value} as {precedence: number, gateway_type: number, algorithm: number, gateway?: string|string[]|number[], public_key: Uint8Array};
    switch (v.gateway_type) {
        case 1:
            v.gateway = IP4ADDR(d);
            break;
        case 2:
            v.gateway = IP6ADDR(d);
            break;
        case 3:
            v.gateway = d.next(DOMAINNAME).value as string[];
            break;
    }
    v.public_key = d.next('opaque').value as Uint8Array;
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
    const vals = {} as Record<string, string>;
    for (let next = d.next('u16'); !next.done; next = d.next('u16')) {
        const key = next.value as number;
        const len = d.next('u16').value as number;
        const val = d.next(`string[${len}]`).value as string;
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

export default function parse(d: Tokenizer, type: RecordType): any {
    return parseToken(d, rdata.get(type) || 'opaque');
}
