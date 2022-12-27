import {RecordType} from "./constants.js";
import {Tokenizer, TokenType} from "./rfc1035.js";

// tslint:disable:no-bitwise

type IP4ADDR = [number, number, number, number];
type IP6ADDR = [number, number, number, number, number, number, number, number];

function IP4ADDR(d: Tokenizer): IP4ADDR {return (new Array(4)).fill(undefined).map(x=>Number(d.next('u8').value)) as IP4ADDR;}
function IP6ADDR(d: Tokenizer): IP6ADDR {return (new Array(8)).fill(undefined).map(x=>Number(d.next('u16').value)) as IP6ADDR;}
function EXP(d: Tokenizer): number {return d.next('u4').value as number * Math.pow(10, d.next('u4').value as number);}

export type OPAQUE = ArrayBuffer;
export type DOMAINNAME = string[];
export const DOMAINNAME = 'string[]';

type _RRDataLayout = ((d: Tokenizer)=>any)|TokenType[]|TokenType;
type RRDataLayout = _RRDataLayout|{[key: string]: _RRDataLayout};

type SIG = {type_covered: number, algorithm: number, labels: number, original_ttl: number, sig_expiration: number, sig_inception: number, key_tag: number, signer: DOMAINNAME, signature: OPAQUE};
type KEY = {flags: number, protocol: number, algorithm: number, public_key: OPAQUE};

export type RDATA = {
    [RecordType.A]: IP4ADDR,
    [RecordType.AAAA]: IP6ADDR,
    [RecordType.SOA]: {MNAME: string[], RNAME: string[], SERIAL: number, REFRESH: number, RETRY: number, EXPIRE: number, MINIMUM: number},
    [RecordType.NS]: DOMAINNAME,
    [RecordType.MD]: DOMAINNAME,
    [RecordType.MF]: DOMAINNAME,
    [RecordType.CNAME]: DOMAINNAME,
    [RecordType.MB]: DOMAINNAME,
    [RecordType.MG]: DOMAINNAME,
    [RecordType.MR]: DOMAINNAME,
    [RecordType.PTR]: DOMAINNAME,
    [RecordType.TXT]: DOMAINNAME,
    [RecordType.DNAME]: DOMAINNAME,
    [RecordType.SPF]: DOMAINNAME,
    [RecordType.NULL]: string,
    [RecordType.X25]: string,
    [RecordType.NSAP]: string,
    [RecordType.WKS]: {ADDRESS: IP4ADDR, PROTOCOL: number, BITMAP: OPAQUE},
    [RecordType.HINFO]: {CPU: string, OS: string},
    [RecordType.MINFO]: {RMAILBX: DOMAINNAME, EMAILBX: DOMAINNAME},
    [RecordType.MX]: {PREFERENCE: number, EXCHANGE: DOMAINNAME},
    [RecordType.RP]: {mbox: DOMAINNAME, txt: DOMAINNAME},
    [RecordType.AFSDB]: {subtype: string, hostname: DOMAINNAME},
    [RecordType.ISDN]: {address: string, sa?: string},
    [RecordType.RT]: {preference: string, 'intermediate-host': DOMAINNAME},
    [RecordType.SIG]: SIG,
    [RecordType.RRSIG]: SIG,
    [RecordType.KEY]: KEY,
    [RecordType.CDNSKEY]: KEY,
    [RecordType.DNSKEY]: {zone_key: boolean, secure_entry_point: boolean, protocol: number, algorithm: number, public_key: OPAQUE, key_tag: number},
    [RecordType.PX]: {PREFERENCE: number, MAP822: DOMAINNAME, MAPX400: DOMAINNAME},
    [RecordType.GPOS]: {LONGITUDE: string, LATITUDE: string, ALTITUDE: string},
    [RecordType.LOC]: {VERSION: number, SIZE: number, HORIZ_PRE: number, VERT_PRE: number, LATITUDE: number, LONGITUDE: number, ALTITUDE: number, size: number, horiz_pre: number, vert_pre: number, latitude: {d: number, m: number, s: number, ns: string}, longitude: {d: number, m: number, s: number, ew: string}, altitude: number},
    [RecordType.NXT]: {next_domain_name: DOMAINNAME, type_bit_map: Set<RecordType>},
    [RecordType.NSEC]: {next_domain_name: DOMAINNAME, type_bit_map: Set<RecordType>},
    [RecordType.EID]: OPAQUE,
    [RecordType.NIMLOC]: OPAQUE,
    [RecordType.ATMA]: OPAQUE,
    [RecordType.A6]: OPAQUE,
    [RecordType.DHCID]: OPAQUE,
    [RecordType.HIP]: OPAQUE,
    [RecordType.NINFO]: OPAQUE,
    [RecordType.RKEY]: OPAQUE,
    [RecordType.TALINK]: OPAQUE,
    [RecordType.OPENPGPKEY]: OPAQUE,
    [RecordType.ZONEMD]: OPAQUE,
    [RecordType.UINFO]: OPAQUE,
    [RecordType.UID]: OPAQUE,
    [RecordType.GID]: OPAQUE,
    [RecordType.UNSPEC]: OPAQUE,
    [RecordType.NID]: OPAQUE,
    [RecordType.L32]: OPAQUE,
    [RecordType.L64]: OPAQUE,
    [RecordType.LP]: OPAQUE,
    [RecordType.EUI64]: OPAQUE,
    [RecordType.AVC]: OPAQUE,
    [RecordType.DOA]: OPAQUE,
    [RecordType.AMTRELAY]: OPAQUE,
    [RecordType.TA]: OPAQUE,
    [RecordType.DLV]: OPAQUE,
    [RecordType.SRV]: {priority: number, weight: number, port: number, target: DOMAINNAME},
    [RecordType.NAPTR]: {ORDER: number, PREFERENCE: number, FLAGS: string, SERVICES: string, REGEXP: string, REPLACEMENT: DOMAINNAME},
    [RecordType.KX]: {PREFERENCE: number, EXCHANGER: DOMAINNAME},
    [RecordType.CERT]: {type: number, key_tag: number, algorithm: number, certificate: OPAQUE},
    [RecordType.SINK]: {coding: number, subcoding: number, data: OPAQUE},
    [RecordType.OPT]: {code: number, length: number, data: OPAQUE},
    [RecordType.APL]: {ADDRESSFAMILY: number, PREFIX: number, N: number, AFDLENGTH: number, AFDPART: OPAQUE},
    [RecordType.DS]: {key_tag: number, algorithm: number, digest_type: number, digest: OPAQUE},
    [RecordType.CDS]: {key_tag: number, algorithm: number, digest_type: number, digest: OPAQUE},
    [RecordType.SSHFP]: {algorithm: number, fp_type: number, fingerprint: OPAQUE},
    [RecordType.IPSECKEY]: {precedence: number, gateway_type: number, algorithm: number, gateway?: IP4ADDR|IP6ADDR|DOMAINNAME, public_key: OPAQUE},
    [RecordType.NSEC3]: {hash_algorithm: number, flags: number, iterations: number, salt: string, next_hashed_owner_name: string, type_bit_map: OPAQUE},
    [RecordType.NSEC3PARAM]: {hash_algorithm: number, flags: number, iterations: number, salt: string},
    [RecordType.TLSA]: {cert_usage: number, selector: number, matching_type: number, cert_assoc_data: OPAQUE},
    [RecordType.SMIMEA]: {cert_usage: number, selector: number, matching_type: number, cert_assoc_data: OPAQUE},
    [RecordType.CSYNC]: {SOA_serial: number, flags: number, type_bit_map: OPAQUE},
    [RecordType.SVCB]: {priority: number, domainname: DOMAINNAME, values: Record<'alpn'|'port'|'esnikeys'|'ipv4hint'|'ipv6hint'|string, string[]>},
    [RecordType.HTTPSSVC]: {priority: number, domainname: DOMAINNAME, values: Record<'alpn'|'port'|'esnikeys'|'ipv4hint'|'ipv6hint'|string, string[]>},
    [RecordType.EUI48]: [number, number, number, number, number, number],
    [RecordType.TSIG]: {algorithm_name: DOMAINNAME, time_signed_upper: number, time_signed: number, fudge: number, MAC: number[], original_id: number, error: number, other_len: number, other_data: OPAQUE},
    [RecordType.URI]: {priority: number, weight: number, target: string},
    [RecordType.CAA]: {flags: number, tag: string, value: string},
}

export const _rdata = new Map<RecordType, RRDataLayout>(); // Maps RecordTypes to RDATA layouts for consumption by parseToken()
_rdata.set(RecordType.A, IP4ADDR);
_rdata.set(RecordType.NS, DOMAINNAME);
_rdata.set(RecordType.MD, DOMAINNAME);
_rdata.set(RecordType.MF, DOMAINNAME);
_rdata.set(RecordType.CNAME, DOMAINNAME);
_rdata.set(RecordType.SOA, {MNAME: DOMAINNAME, RNAME: DOMAINNAME, SERIAL: 'u32', REFRESH: 'u32', RETRY: 'u32', EXPIRE: 'u32', MINIMUM: 'u32'});
_rdata.set(RecordType.MB, DOMAINNAME);
_rdata.set(RecordType.MG, DOMAINNAME);
_rdata.set(RecordType.MR, DOMAINNAME);
_rdata.set(RecordType.NULL, 'string[*]');
_rdata.set(RecordType.WKS, {ADDRESS: IP4ADDR, PROTOCOL: 'u8', BITMAP: 'opaque'});
_rdata.set(RecordType.PTR, DOMAINNAME);
_rdata.set(RecordType.HINFO, {CPU: 'string', OS: 'string'});
_rdata.set(RecordType.MINFO, {RMAILBX: DOMAINNAME, EMAILBX: DOMAINNAME});
_rdata.set(RecordType.MX, {PREFERENCE: 's16', EXCHANGE: DOMAINNAME});
_rdata.set(RecordType.TXT, 'string[]');
_rdata.set(RecordType.RP, {mbox: DOMAINNAME, txt: DOMAINNAME});
_rdata.set(RecordType.AFSDB, {subtype: 's16', hostname: DOMAINNAME});
_rdata.set(RecordType.X25, 'string');
_rdata.set(RecordType.ISDN, (d: Tokenizer): {address: string, sa?: string}=>{const v: {address: string, sa?: string}={address: d.next('string').value as string, sa: undefined}; const n = d.next(); v.sa = n.done ? undefined : n.value as string; return v;});
_rdata.set(RecordType.RT, {preference: 's16', 'intermediate-host': DOMAINNAME});
_rdata.set(RecordType.NSAP, 'string');
_rdata.set(RecordType['NSAP-PTR'], 'string');
_rdata.set(RecordType.SIG, {type_covered: 'u16', algorithm: 'u8', labels: 'u8', original_ttl: 'u32', sig_expiration: 'u32', sig_inception: 'u32', key_tag: 'u16', signer: DOMAINNAME, signature: 'opaque'});
_rdata.set(RecordType.KEY, {flags: 'u16', protocol: 'u8', algorithm: 'u8', public_key: 'opaque'});
_rdata.set(RecordType.PX, {PREFERENCE: 's16', MAP822: DOMAINNAME, MAPX400: DOMAINNAME});
_rdata.set(RecordType.GPOS, {LONGITUDE: 'string', LATITUDE: 'string', ALTITUDE: 'string'});
_rdata.set(RecordType.AAAA, IP6ADDR);
_rdata.set(RecordType.LOC, (d: Tokenizer)=>{
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
_rdata.set(RecordType.NXT, {next_domain_name: DOMAINNAME, type_bit_map: (d: Tokenizer)=>{
    const types = new Set<RecordType>();
    while (!d.next().done) {
        const window = d.next('u8').value as number * 256;
        const length = d.next('u8').value as number * 8;
        for (let bit = 0; bit < length; ++bit) {
            if (d.next('bit').value) types.add(window + bit);
        }
    }
    return types;
}});
_rdata.set(RecordType.EID, 'opaque');
_rdata.set(RecordType.NIMLOC, 'opaque');
_rdata.set(RecordType.SRV, {priority: 'u16', weight: 'u16', port: 'u16', target: DOMAINNAME});
_rdata.set(RecordType.ATMA, 'opaque');
_rdata.set(RecordType.NAPTR, {ORDER: 'u16', PREFERENCE: 'u16', FLAGS: 'string', SERVICES: 'string', REGEXP: 'string', REPLACEMENT: DOMAINNAME});
_rdata.set(RecordType.KX, {PREFERENCE: 'u16', EXCHANGER: DOMAINNAME});
_rdata.set(RecordType.CERT, {type: 'u16', key_tag: 'u16', algorithm: 'u8', certificate: 'opaque'});
_rdata.set(RecordType.A6, 'opaque');
_rdata.set(RecordType.DNAME, DOMAINNAME);
_rdata.set(RecordType.SINK, {coding: 'u8', subcoding: 'u8', data: 'opaque'});
_rdata.set(RecordType.OPT, {code: 'u16', length: 'u16', data: 'opaque'});
_rdata.set(RecordType.APL, {ADDRESSFAMILY: 'u16', PREFIX: 'u8', N: 'bit', AFDLENGTH: (d: Tokenizer): number=>(new Array(7)).fill(undefined).map(()=>d.next('bit').value as number).reduce((acc: number, cur: number)=>((acc<<1)+cur), 0), AFDPART: 'opaque'});
_rdata.set(RecordType.DS, {key_tag: 'u16', algorithm: 'u8', digest_type: 'u8', digest: 'opaque'});
_rdata.set(RecordType.SSHFP, {algorithm: 'u8', fp_type: 'u8', fingerprint: 'opaque'});
_rdata.set(RecordType.IPSECKEY, (d: Tokenizer)=>{
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
_rdata.set(RecordType.RRSIG, _rdata.get(RecordType.SIG));
_rdata.set(RecordType.NSEC, _rdata.get(RecordType.NXT));
_rdata.set(RecordType.DNSKEY, (d: Tokenizer)=>{
    const val = parseToken(d, {
        reserved1: 'bit',
        reserved2: 'bit',
        reserved3: 'bit',
        reserved4: 'bit',
        reserved5: 'bit',
        reserved6: 'bit',
        reserved7: 'bit',
        zone_key: 'bit',
        reserved9: 'bit',
        reserved10: 'bit',
        reserved11: 'bit',
        reserved12: 'bit',
        reserved13: 'bit',
        reserved14: 'bit',
        reserved15: 'bit',
        secure_entry_point: 'bit',
        protocol: 'u8',
        algorithm: 'u8',
    });
    if (val.algorithm === 1) throw new Error('RSA/MD5 key_tag not implemented'); // TODO https://datatracker.ietf.org/doc/html/rfc4034#appendix-B.1
    else val.key_tag = key_tag(d.next('view').value as DataView);
    val.public_key = d.next('opaque').value as ArrayBuffer;
    return val;
});
_rdata.set(RecordType.DHCID, 'opaque');
_rdata.set(RecordType.NSEC3, {hash_algorithm: 'u8', flags: 'u8', iterations: 'u16', salt: 'string', next_hashed_owner_name: 'string', type_bit_map: 'opaque'});  // TODO https://datatracker.ietf.org/doc/html/rfc5155
_rdata.set(RecordType.NSEC3PARAM, {hash_algorithm: 'u8', flags: 'u8', iterations: 'u16', salt: 'string'});
_rdata.set(RecordType.TLSA, {cert_usage: 'u8', selector: 'u8', matching_type: 'u8', cert_assoc_data: 'opaque'});
_rdata.set(RecordType.SMIMEA, _rdata.get(RecordType.TLSA));
_rdata.set(RecordType.HIP, 'opaque');
_rdata.set(RecordType.NINFO, 'opaque');
_rdata.set(RecordType.RKEY, 'opaque');
_rdata.set(RecordType.TALINK, 'opaque');
_rdata.set(RecordType.CDS, _rdata.get(RecordType.DS));
_rdata.set(RecordType.CDNSKEY, _rdata.get(RecordType.DNSKEY));
_rdata.set(RecordType.OPENPGPKEY, 'opaque');
_rdata.set(RecordType.CSYNC, {SOA_serial: 'u32', flags: 'u16', type_bit_map: 'opaque'});
_rdata.set(RecordType.ZONEMD, 'opaque');
_rdata.set(RecordType.SVCB, {priority: 'u16', domainname: DOMAINNAME, values: (d: Tokenizer)=>{
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
_rdata.set(RecordType.HTTPSSVC, _rdata.get(RecordType.SVCB));
_rdata.set(RecordType.SPF, 'string[]');
_rdata.set(RecordType.UINFO, 'opaque');
_rdata.set(RecordType.UID, 'opaque');
_rdata.set(RecordType.GID, 'opaque');
_rdata.set(RecordType.UNSPEC, 'opaque');
_rdata.set(RecordType.NID, 'opaque');
_rdata.set(RecordType.L32, 'opaque');
_rdata.set(RecordType.L64, 'opaque');
_rdata.set(RecordType.LP, 'opaque');
_rdata.set(RecordType.EUI48, (d: Tokenizer)=>(new Array(6)).fill(undefined).map(x=>d.next('u8').value as number));
_rdata.set(RecordType.EUI64, 'opaque');
_rdata.set(RecordType.TSIG, {algorithm_name: DOMAINNAME, time_signed_upper: 'u16', time_signed: 'u32', fudge: 'u16', MAC: (d: Tokenizer)=>(new Array(d.next('u16').value as number)).fill(undefined).map(x=>d.next('u8').value as number), original_id: 'u16', error: 'u16', other_len: 'u16', other_data: 'opaque'});
// Not RR types
// rdata.set(RecordType.IXFR, 'opaque');
// rdata.set(RecordType.AXFR, 'opaque');
// rdata.set(RecordType.MAILB, 'opaque');
// rdata.set(RecordType.MAILA, 'opaque');
// rdata.set(RecordType['*'], 'opaque');
_rdata.set(RecordType.URI, {priority: 'u16', weight: 'u16', target: 'string[*]'});
_rdata.set(RecordType.CAA, {flags: 'u8', tag: 'string', value: 'string[*]'});
_rdata.set(RecordType.AVC, 'opaque');
_rdata.set(RecordType.DOA, 'opaque');
_rdata.set(RecordType.AMTRELAY, 'opaque');
_rdata.set(RecordType.TA, 'opaque');
_rdata.set(RecordType.DLV, 'opaque');

/**
 * Helper to allow representing RDATA structures with functions, objects, or string literals
 * @param d Tokenizer initialised with data to parse
 * @param layout RDATA layout used to convert wireformat to native data structure
 */
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

/**
 * Parse RDATA into native data structure
 * @param d Tokenizer initialised with data to parse
 * @param type RecordType of RDATA
 */
export default function parse<T extends keyof RDATA>(d: Tokenizer, type: RecordType): RDATA[T] {
    return parseToken(d, _rdata.get(type) || 'opaque');
}

/**
 * Calculates a key_tag value for a given certificate for the CERT or DNSKEY record
 * @param rdata Buffer containing rdata wireformat data
 * @return key_tag that helps identify certificate record (not unique)
 */
export function key_tag(rdata: DataView): number {
    const count = rdata.byteLength - (rdata.byteLength % 2);
    let tag = 0;
    for (let i = 0; i < count; i += 2) tag += rdata.getUint16(i);
    if (count > rdata.byteLength) rdata.getUint8(count);
    return (((tag >>> 16) & 0xFFFF) + tag) & 0xFFFF;
}
