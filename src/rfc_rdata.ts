import {RecordType} from "./constants.js";
import {Tokenizer, TokenType} from "./bin_util.js";
import {base32_encode} from "./base32.js"; // WTF?! why is NSEC3 the special snowflake that uses base32 where everything else uses hex or base64 :(

// eslint-disable:no-bitwise

type IP4ADDR = [number, number, number, number];
type IP6ADDR = [number, number, number, number, number, number, number, number];

function IP4ADDR(d: Tokenizer): IP4ADDR {
    return (new Array(4)).fill(undefined).map(() => Number(d.next('u8').value)) as IP4ADDR;
}

function IP4ADDRTxt(ip: IP4ADDR) {
    return ip.join('.');
}

function IP6ADDR(d: Tokenizer): IP6ADDR {
    return (new Array(8)).fill(undefined).map(() => Number(d.next('u16').value)) as IP6ADDR;
}

function IP6ADDRTxt(ip: IP6ADDR) {
    return ip.map(d=>d.toString(16).padStart(2, '0')).join(':');
}

function EXP(d: Tokenizer): number {
    return d.next('u4').value as number * Math.pow(10, d.next('u4').value as number);
}

function type_bit_map(d: Tokenizer) { // https://www.rfc-editor.org/rfc/rfc4034#section-4.1.2
    const types = new Set<RecordType>();
    while (!d.next().done) {
        const window = d.next('u8').value as number * 256;
        const length = d.next('u8').value as number * 8;
        for (let bit = 0; bit < length; ++bit) {
            if (d.next('bit').value) types.add(window + bit);
        }
    }
    return types;
}

function TYPEBitmapTxt(types: Set<RecordType>) {
    return Array.from(types).map(t=>`TYPE${t}`).join(' ');
}

export type OPAQUE = ArrayBuffer;

function base64_encode(data: OPAQUE) {
    return btoa(Array.from(new Uint8Array(data), b => String.fromCharCode(b)).join(''));
}

function HexTxt(data: ArrayBuffer) {
    return Array.from(new Uint8Array(data), b => b.toString(16).padStart(2, '0')).join('');
}

export type DOMAINNAME = string[];
export const DOMAINNAME = 'string[]';

function DOMAINNAMETxt(name: DOMAINNAME) {
    return name.join('.') + (name.at(-1) !== '' ? '.' : '');
}

export function domainNameEq(a: DOMAINNAME, b: DOMAINNAME): boolean {
    if (a.length !== b.length) return false;
    return a.every((label, i) => label === b[i]);
}

type RRDataLayout = ((d: Tokenizer) => any) | TokenType[] | TokenType | { [key: string]: RRDataLayout };

type SIG = { type_covered: RecordType, algorithm: number, labels: number, original_ttl: number, sig_expiration: number, sig_inception: number, key_tag: number, signer: DOMAINNAME, signature: OPAQUE };
type KEY = { NOKEY: boolean, NOAUTH: boolean, NOCONF: boolean, NAMTYPE: number, sig: number, protocol: number, algorithm: number, public_key: OPAQUE };

const NSAPPTR = RecordType['NSAP-PTR'];
export type RDATA = {
    [RecordType.A]: IP4ADDR,
    [RecordType.AAAA]: IP6ADDR,
    [RecordType.SOA]: { MNAME: string[], RNAME: string[], SERIAL: number, REFRESH: number, RETRY: number, EXPIRE: number, MINIMUM: number },
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
    [NSAPPTR]: string,
    [RecordType.WKS]: { ADDRESS: IP4ADDR, PROTOCOL: number, BITMAP: OPAQUE },
    [RecordType.HINFO]: { CPU: string, OS: string },
    [RecordType.MINFO]: { RMAILBX: DOMAINNAME, EMAILBX: DOMAINNAME },
    [RecordType.MX]: { PREFERENCE: number, EXCHANGE: DOMAINNAME },
    [RecordType.RP]: { mbox: DOMAINNAME, txt: DOMAINNAME },
    [RecordType.AFSDB]: { subtype: string, hostname: DOMAINNAME },
    [RecordType.ISDN]: { address: string, sa?: string },
    [RecordType.RT]: { preference: string, 'intermediate-host': DOMAINNAME },
    [RecordType.SIG]: SIG,
    [RecordType.RRSIG]: SIG,
    [RecordType.KEY]: KEY,
    [RecordType.CDNSKEY]: KEY,
    [RecordType.DNSKEY]: { zone_key: boolean, secure_entry_point: boolean, protocol: number, algorithm: number, public_key: OPAQUE, key_tag: number },
    [RecordType.PX]: { PREFERENCE: number, MAP822: DOMAINNAME, MAPX400: DOMAINNAME },
    [RecordType.GPOS]: { LONGITUDE: string, LATITUDE: string, ALTITUDE: string },
    [RecordType.LOC]: { VERSION: number, SIZE: number, HORIZ_PRE: number, VERT_PRE: number, LATITUDE: number, LONGITUDE: number, ALTITUDE: number, size: number, horiz_pre: number, vert_pre: number, latitude: { d: number, m: number, s: number, ns: string }, longitude: { d: number, m: number, s: number, ew: string }, altitude: number },
    [RecordType.NXT]: { next_domain_name: DOMAINNAME, type_bit_map: Set<RecordType> },
    [RecordType.NSEC]: { next_domain_name: DOMAINNAME, type_bit_map: Set<RecordType> },
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
    [RecordType.SRV]: { priority: number, weight: number, port: number, target: DOMAINNAME },
    [RecordType.NAPTR]: { ORDER: number, PREFERENCE: number, FLAGS: string, SERVICES: string, REGEXP: string, REPLACEMENT: DOMAINNAME },
    [RecordType.KX]: { PREFERENCE: number, EXCHANGER: DOMAINNAME },
    [RecordType.CERT]: { type: number, key_tag: number, algorithm: number, certificate: OPAQUE },
    [RecordType.SINK]: { coding: number, subcoding: number, data: OPAQUE },
    [RecordType.OPT]: { code: number, length: number, data: OPAQUE },
    [RecordType.APL]: [{ ADDRESSFAMILY: number, PREFIX: number, N: number, AFDLENGTH: number, AFDPART: IP4ADDR | IP6ADDR | any }],
    [RecordType.DS]: { key_tag: number, algorithm: number, digest_type: number, digest: OPAQUE },
    [RecordType.CDS]: { key_tag: number, algorithm: number, digest_type: number, digest: OPAQUE },
    [RecordType.SSHFP]: { algorithm: number, fp_type: number, fingerprint: OPAQUE },
    [RecordType.IPSECKEY]: { precedence: number, gateway_type: number, algorithm: number, gateway?: IP4ADDR | IP6ADDR | DOMAINNAME, public_key: OPAQUE },
    [RecordType.NSEC3]: { hash_algorithm: number, opt_out: boolean, iterations: number, salt: ArrayBuffer, next_hashed_owner_name: ArrayBuffer, type_bit_map: Set<RecordType> },
    [RecordType.NSEC3PARAM]: { hash_algorithm: number, flags: number, iterations: number, salt: ArrayBuffer },
    [RecordType.TLSA]: { cert_usage: number, selector: number, matching_type: number, cert_assoc_data: OPAQUE },
    [RecordType.SMIMEA]: { cert_usage: number, selector: number, matching_type: number, cert_assoc_data: OPAQUE },
    [RecordType.CSYNC]: { SOA_serial: number, soaminimum: boolean, immediate: boolean, type_bit_map: Set<RecordType> },
    [RecordType.SVCB]: { priority: number, domainname: DOMAINNAME, values: Record<'alpn' | 'port' | 'esnikeys' | 'ipv4hint' | 'ipv6hint' | string, string[]> },
    [RecordType.HTTPSSVC]: { priority: number, domainname: DOMAINNAME, values: Record<'alpn' | 'port' | 'esnikeys' | 'ipv4hint' | 'ipv6hint' | string, string[]> },
    [RecordType.EUI48]: [number, number, number, number, number, number],
    [RecordType.TSIG]: { algorithm_name: DOMAINNAME, time_signed: BigInt, fudge: number, MAC: number[], original_id: number, error: number, other_len: number, other_data: OPAQUE },
    [RecordType.URI]: { priority: number, weight: number, target: string },
    [RecordType.CAA]: { issuer_critical: boolean, tag: string, value: string },
}

export const _rdata = new Map<RecordType, RRDataLayout>(); // Maps RecordTypes to RDATA layouts for consumption by parseToken()
// TODO Make each RDATA a full fledged class with toString() and array/iterator access if necessary
// TODO Some of the text representations of rdata are complete guesses and should not be trusted to be accurate
const WIPWarningMessage = ' ; ! WIP, the text representation of this record is incomplete';
function UnimplementedField(rdata: ArrayBuffer) {
    return base64_encode(rdata) + WIPWarningMessage;
}
export const _rtext = new Map<RecordType, (rdata: RDATA[keyof RDATA])=>string>();  // Maps RecordTypes to functions that return the textual representation of the rdata: https://datatracker.ietf.org/doc/html/rfc1034#section-3.6.1
_rdata.set(RecordType.A, IP4ADDR);
_rtext.set(RecordType.A, IP4ADDRTxt);
_rdata.set(RecordType.NS, DOMAINNAME);
_rtext.set(RecordType.NS, DOMAINNAMETxt);
_rdata.set(RecordType.MD, DOMAINNAME);
_rtext.set(RecordType.MD, DOMAINNAMETxt);
_rdata.set(RecordType.MF, DOMAINNAME);
_rtext.set(RecordType.MF, DOMAINNAMETxt);
_rdata.set(RecordType.CNAME, DOMAINNAME);
_rtext.set(RecordType.CNAME, DOMAINNAMETxt);
_rdata.set(RecordType.SOA, {
    MNAME: DOMAINNAME,
    RNAME: DOMAINNAME,
    SERIAL: 'u32',
    REFRESH: 'u32',
    RETRY: 'u32',
    EXPIRE: 'u32',
    MINIMUM: 'u32'
});
_rtext.set(RecordType.SOA, (rdata: RDATA[RecordType.SOA])=>`${DOMAINNAMETxt(rdata.MNAME)} ${DOMAINNAMETxt(rdata.RNAME)} ${rdata.SERIAL} ${rdata.REFRESH} ${rdata.RETRY} ${rdata.EXPIRE} ${rdata.MINIMUM}`);
_rdata.set(RecordType.MB, DOMAINNAME);
_rtext.set(RecordType.MB, DOMAINNAMETxt);
_rdata.set(RecordType.MG, DOMAINNAME);
_rtext.set(RecordType.MG, DOMAINNAMETxt);
_rdata.set(RecordType.MR, DOMAINNAME);
_rtext.set(RecordType.MR, DOMAINNAMETxt);
_rdata.set(RecordType.NULL, 'string[*]');
_rtext.set(RecordType.NULL, (rdata: RDATA[RecordType.NULL]) => rdata);
_rdata.set(RecordType.WKS, {ADDRESS: IP4ADDR, PROTOCOL: 'u8', BITMAP: 'opaque'});
_rtext.set(RecordType.WKS, (rdata: RDATA[RecordType.WKS]) => `${IP4ADDRTxt(rdata.ADDRESS)} ${rdata.PROTOCOL} ${base64_encode(rdata.BITMAP)} ; ! WIP, the text representation of this record is incomplete`); //TODO need to locate the protocol and bitmap databases to convert to text
_rdata.set(RecordType.PTR, DOMAINNAME);
_rtext.set(RecordType.PTR, DOMAINNAMETxt);
_rdata.set(RecordType.HINFO, {CPU: 'string', OS: 'string'});
_rtext.set(RecordType.HINFO, (rdata: RDATA[RecordType.HINFO]) => `${rdata.CPU} ${rdata.OS}`);
_rdata.set(RecordType.MINFO, {RMAILBX: DOMAINNAME, EMAILBX: DOMAINNAME});
_rtext.set(RecordType.MINFO, (rdata: RDATA[RecordType.MINFO]) => `${DOMAINNAMETxt(rdata.RMAILBX)} ${DOMAINNAMETxt(rdata.EMAILBX)}`);
_rdata.set(RecordType.MX, {PREFERENCE: 's16', EXCHANGE: DOMAINNAME});
_rtext.set(RecordType.MX, (rdata: RDATA[RecordType.MX]) => `${rdata.PREFERENCE} ${DOMAINNAMETxt(rdata.EXCHANGE)}`);
_rdata.set(RecordType.TXT, 'string[]');
_rtext.set(RecordType.TXT, (rdata: RDATA[RecordType.TXT]) => '"' + rdata.join('" "') + '"');
_rdata.set(RecordType.RP, {mbox: DOMAINNAME, txt: DOMAINNAME});
_rtext.set(RecordType.RP, (rdata: RDATA[RecordType.RP]) => `${DOMAINNAMETxt(rdata.mbox)} ${DOMAINNAMETxt(rdata.txt)}`);
_rdata.set(RecordType.AFSDB, {subtype: 's16', hostname: DOMAINNAME});
_rtext.set(RecordType.AFSDB, (rdata: RDATA[RecordType.AFSDB]) => `${rdata.subtype} ${DOMAINNAMETxt(rdata.hostname)}`);
_rdata.set(RecordType.X25, 'string');
_rtext.set(RecordType.X25, (rdata: RDATA[RecordType.X25]) => rdata);
_rdata.set(RecordType.ISDN, (d: Tokenizer): { address: string, sa?: string } => {
    const v: { address: string, sa?: string } = {address: d.next('string').value as string, sa: undefined};
    const n = d.next();
    v.sa = n.done ? undefined : n.value as string;
    return v;
});
_rtext.set(RecordType.ISDN, (rdata: RDATA[RecordType.ISDN]) => rdata.address + rdata.sa === undefined ? '' : (' ' + rdata.sa));
_rdata.set(RecordType.RT, {preference: 's16', 'intermediate-host': DOMAINNAME});
_rtext.set(RecordType.RT, (rdata: RDATA[RecordType.RT]) => `${rdata.preference} ${DOMAINNAMETxt(rdata['intermediate-host'])}`);
_rdata.set(RecordType.NSAP, 'string');
_rtext.set(RecordType.NSAP, (rdata: RDATA[RecordType.NSAP]) => rdata);
_rdata.set(RecordType['NSAP-PTR'], 'string');
_rtext.set(RecordType['NSAP-PTR'], (rdata: RDATA[typeof NSAPPTR]) => rdata);
_rdata.set(RecordType.SIG, {
    type_covered: 'u16',
    algorithm: 'u8',
    labels: 'u8',
    original_ttl: 'u32',
    sig_expiration: 'u32',
    sig_inception: 'u32',
    key_tag: 'u16',
    signer: DOMAINNAME,
    signature: 'opaque'
});
_rtext.set(RecordType.SIG, (rdata: RDATA[RecordType.SIG]) => `TYPE${rdata.type_covered} ${rdata.algorithm} ${rdata.labels} ${rdata.original_ttl} ${rdata.sig_expiration} ${rdata.sig_inception} ${rdata.key_tag} ${DOMAINNAMETxt(rdata.signer)} ${base64_encode(rdata.signature)}`);
_rdata.set(RecordType.KEY, (d: Tokenizer) => {
    const val = parseToken(d, { // https://www.rfc-editor.org/rfc/rfc2535#section-3.1
        KEYTYPE: 'u2',
        reserved1: 'bit',
        XT: 'bit',
        reserved2: 'bit',
        reserved3: 'bit',
        NAMTYPE: 'u2',
        reserved4: 'bit',
        reserved5: 'bit',
        reserved6: 'bit',
        reserved7: 'bit',
        sig: 'u4',
        protocol: 'u8',
        algorithm: 'u8',
    });
    val.NOCONF = val.KEYTYPE === 1; // confidentiality use prohibited
    val.NOAUTH = val.KEYTYPE === 2; // authentication use prohibited
    val.NOKEY = val.KEYTYPE === 3; // no key present
    if (val.XT) val.extra_flags = d.next('u16').value as number;
    val.public_key = d.next('opaque').value as ArrayBuffer;
    return val;
});
_rtext.set(RecordType.KEY, (rdata: RDATA[RecordType.KEY]) => [(rdata.NOCONF ? 'NOCONF' : ''), (rdata.NOAUTH ? 'NOAUTH' : ''), (rdata.NOKEY ? 'NOKEY' : ''), ((rdata as unknown as {XT: number}).XT ? 'EXTEND' : ''), ({0: '', 1: 'ZONE', 2: 'HOST'}[rdata.NAMTYPE]), `SIG${rdata.sig}`].filter(f=>f.length > 0).join('|') + ` ${rdata.protocol} ${rdata.algorithm}` + (rdata.NOKEY ? '' : ' ' + base64_encode(rdata.public_key)));
_rdata.set(RecordType.PX, {PREFERENCE: 's16', MAP822: DOMAINNAME, MAPX400: DOMAINNAME});
_rtext.set(RecordType.PX, (rdata: RDATA[RecordType.PX]) =>`${rdata.PREFERENCE} ${DOMAINNAMETxt(rdata.MAP822)} ${DOMAINNAMETxt(rdata.MAPX400)}`);
_rdata.set(RecordType.GPOS, {LONGITUDE: 'string', LATITUDE: 'string', ALTITUDE: 'string'});
_rtext.set(RecordType.GPOS, (rdata: RDATA[RecordType.GPOS]) =>`${rdata.LONGITUDE} ${rdata.LATITUDE} ${rdata.ALTITUDE}`);
_rdata.set(RecordType.AAAA, IP6ADDR);
_rtext.set(RecordType.AAAA, IP6ADDRTxt);
_rdata.set(RecordType.LOC, (d: Tokenizer) => {
    const val = parseToken(d, {
        VERSION: 'u8',
        SIZE: EXP,
        HORIZ_PRE: EXP,
        VERT_PRE: EXP,
        LATITUDE: 'u32',
        LONGITUDE: 'u32',
        ALTITUDE: 'u32'
    });
    const dms = (n: number) => ({
        d: Math.abs(Math.trunc(n / 3600000)),
        m: Math.abs(Math.trunc((n % 3600000) / 60000)),
        s: Math.abs(((n % 3600000) % 60000) / 1000)
    });
    val.size = val.SIZE / 100;
    val.horiz_pre = val.HORIZ_PRE / 100;
    val.vert_pre = val.VERT_PRE / 100;
    val.latitude = dms(val.LATITUDE - 2 ** 31);
    val.latitude.ns = val.LATITUDE <= 0 ? "N" : "S";
    val.longitude = dms(val.LONGITUDE - 2 ** 31);
    val.longitude.ew = val.LONGITUDE <= 0 ? "E" : "W";
    val.altitude = val.ALTITUDE / 100 - 100000;
    return val;
});
_rtext.set(RecordType.LOC, (rdata: RDATA[RecordType.LOC])=>`${rdata.latitude.d} ${rdata.latitude.m} ${rdata.latitude.s} ${rdata.latitude.ns} ${rdata.longitude.d} ${rdata.longitude.m} ${rdata.longitude.s} ${rdata.longitude.ew} ${rdata.altitude} ${rdata.size} ${rdata.horiz_pre} ${rdata.vert_pre}`)
_rdata.set(RecordType.NXT, {next_domain_name: DOMAINNAME, type_bit_map});
_rtext.set(RecordType.NXT, (rdata: RDATA[RecordType.NXT])=>`${DOMAINNAMETxt(rdata.next_domain_name)} ${Array.from(rdata.type_bit_map).map(t => RecordType[t]).join(' ')}`);
_rdata.set(RecordType.EID, 'opaque');
_rtext.set(RecordType.EID, HexTxt);
_rdata.set(RecordType.NIMLOC, 'opaque');
_rtext.set(RecordType.NIMLOC, HexTxt);
_rdata.set(RecordType.SRV, {priority: 'u16', weight: 'u16', port: 'u16', target: DOMAINNAME});
_rtext.set(RecordType.SRV, (rdata: RDATA[RecordType.SRV])=>`${rdata.priority} ${rdata.weight} ${rdata.port} ${DOMAINNAMETxt(rdata.target)}`);
_rdata.set(RecordType.ATMA, 'opaque'); // TODO
_rtext.set(RecordType.ATMA, UnimplementedField);
_rdata.set(RecordType.NAPTR, {
    ORDER: 'u16',
    PREFERENCE: 'u16',
    FLAGS: 'string',
    SERVICES: 'string',
    REGEXP: 'string',
    REPLACEMENT: DOMAINNAME
});
_rtext.set(RecordType.NAPTR, (rdata: RDATA[RecordType.NAPTR])=>`${rdata.ORDER} ${rdata.PREFERENCE} "${rdata.FLAGS}" "${rdata.SERVICES}" "${rdata.REGEXP.replace(/\\/g, '\\\\')}" ${DOMAINNAMETxt(rdata.REPLACEMENT)}`);
_rdata.set(RecordType.KX, {PREFERENCE: 'u16', EXCHANGER: DOMAINNAME});
_rtext.set(RecordType.KX, (rdata: RDATA[RecordType.KX]) => `${rdata.PREFERENCE} ${DOMAINNAMETxt(rdata.EXCHANGER)}`);
_rdata.set(RecordType.CERT, {type: 'u16', key_tag: 'u16', algorithm: 'u8', certificate: 'opaque'});
_rtext.set(RecordType.CERT, (rdata: RDATA[RecordType.CERT])=>`${rdata.type} ${rdata.key_tag} ${rdata.algorithm} ${base64_encode(rdata.certificate)}`)
_rdata.set(RecordType.A6, 'opaque'); // Obsolete
_rtext.set(RecordType.A6, UnimplementedField);
_rdata.set(RecordType.DNAME, DOMAINNAME);
_rtext.set(RecordType.DNAME, DOMAINNAMETxt);
_rdata.set(RecordType.SINK, {coding: 'u8', subcoding: 'u8', data: 'opaque'});
_rtext.set(RecordType.SINK, (rdata: RDATA[RecordType.SINK])=>`${rdata.coding} ${rdata.subcoding} ${base64_encode(rdata.data)}`);
_rdata.set(RecordType.OPT, {code: 'u16', length: 'u16', data: 'opaque'});
_rtext.set(RecordType.OPT, (rdata: RDATA[RecordType.OPT])=>`${rdata.code} ${rdata.length} ${base64_encode(rdata.data)}`);
_rdata.set(RecordType.APL, (d: Tokenizer) => {
    const l = [];
    while (!d.next().done) {
        const ap: RDATA[RecordType.APL][number] = parseToken(d, {
            ADDRESSFAMILY: 'u16',
            PREFIX: 'u8',
            N: 'bit',
            AFDLENGTH: (d: Tokenizer): number => (new Array(7)).fill(undefined).map(() => d.next('bit').value as number).reduce((acc: number, cur: number) => ((acc << 1) + cur), 0),
        });
        let temp;
        switch (ap.ADDRESSFAMILY) {
            // https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml#address-family-numbers-2
            case 1:
                ap.AFDPART = (new Array(ap.AFDLENGTH)).fill(0).map(() => Number(d.next('u8').value)) as IP4ADDR;
                break;
            case 2:
                temp = new Uint8Array(16);
                for (let i = 0; i < ap.AFDLENGTH; ++i) temp[i] = d.next('u8').value as number;
                ap.AFDPART = Array.from(new Uint16Array(temp)) as IP6ADDR;
                break;
            default:
                temp = new Uint8Array(ap.AFDLENGTH);
                for (let i = 0; i < ap.AFDLENGTH; ++i) ap.AFDPART[i] = d.next('u8').value;
                ap.AFDPART = temp.buffer;
                break;
        }
        l.push(ap);
    }
    return l;
});
_rtext.set(RecordType.APL, (rdata: RDATA[RecordType.APL])=> rdata.map(ap=> {
    let addr;
    let warn = '';
    switch (ap.ADDRESSFAMILY) {
        case 1:
            addr = IP4ADDRTxt(ap.AFDPART);
            break;
        case 2:
            addr = IP6ADDRTxt(ap.AFDPART);
            break;
        default:
            addr = base64_encode(ap.AFDPART);
            warn = WIPWarningMessage;
    }
    return `${ap.N ? '!' : ''}${ap.ADDRESSFAMILY}:${addr}/${ap.PREFIX}` + warn;
}).join(' '));
_rdata.set(RecordType.DS, {key_tag: 'u16', algorithm: 'u8', digest_type: 'u8', digest: 'opaque'});
_rtext.set(RecordType.DS, (rdata: RDATA[RecordType.DS])=>`${rdata.key_tag} ${rdata.algorithm} ${rdata.digest_type} ${HexTxt(rdata.digest)}`);
_rdata.set(RecordType.SSHFP, {algorithm: 'u8', fp_type: 'u8', fingerprint: 'opaque'});
_rtext.set(RecordType.SSHFP, (rdata: RDATA[RecordType.SSHFP])=>`${rdata.algorithm} ${rdata.fp_type} ${HexTxt(rdata.fingerprint)}`);
_rdata.set(RecordType.IPSECKEY, (d: Tokenizer) => {
    const v = {
        precedence: d.next('u8').value,
        gateway_type: d.next('u8').value,
        algorithm: d.next('u8').value
    } as { precedence: number, gateway_type: number, algorithm: number, gateway?: IP4ADDR | IP6ADDR | DOMAINNAME, public_key: OPAQUE };
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
_rtext.set(RecordType.IPSECKEY, (rdata: RDATA[RecordType.IPSECKEY])=> {
    let gateway;
    switch (rdata.gateway_type) {
        case 1:
            gateway = IP4ADDRTxt(rdata.gateway as IP4ADDR);
            break;
        case 2:
            gateway = IP6ADDRTxt(rdata.gateway as IP6ADDR);
            break;
        case 3:
            gateway = DOMAINNAMETxt(rdata.gateway as DOMAINNAME);
            break;
    }
    return `${rdata.precedence} ${rdata.gateway_type} ${gateway} ${base64_encode(rdata.public_key)}`;
});
_rdata.set(RecordType.RRSIG, _rdata.get(RecordType.SIG));
_rtext.set(RecordType.RRSIG, _rtext.get(RecordType.SIG));
_rdata.set(RecordType.NSEC, _rdata.get(RecordType.NXT));
_rtext.set(RecordType.NSEC, _rtext.get(RecordType.NXT));
_rdata.set(RecordType.DNSKEY, (d: Tokenizer) => {
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
_rtext.set(RecordType.DNSKEY, (rdata: RDATA[RecordType.DNSKEY])=>`${(rdata.zone_key ? 256 : 0) & (rdata.secure_entry_point ? 257 : 0)} ${rdata.protocol} ${rdata.algorithm} ${base64_encode(rdata.public_key)}`);
_rdata.set(RecordType.DHCID, 'opaque');
_rtext.set(RecordType.DHCID, base64_encode);
_rdata.set(RecordType.NSEC3, {
    hash_algorithm: 'u8',
    reserved1: 'bit',
    reserved2: 'bit',
    reserved3: 'bit',
    reserved4: 'bit',
    reserved5: 'bit',
    reserved6: 'bit',
    reserved7: 'bit',
    opt_out: 'bit',
    iterations: 'u16',
    salt: 'bytes',
    next_hashed_owner_name: 'bytes',
    type_bit_map
});
_rtext.set(RecordType.NSEC3, (rdata: RDATA[RecordType.NSEC3])=>`${rdata.hash_algorithm} ${rdata.opt_out ? 1 : 0} ${rdata.iterations} ${rdata.salt.byteLength === 0 ? '-' : HexTxt(rdata.salt)} ${base32_encode(rdata.next_hashed_owner_name)} ${TYPEBitmapTxt(rdata.type_bit_map)}`);
_rdata.set(RecordType.NSEC3PARAM, {hash_algorithm: 'u8', flags: 'u8', iterations: 'u16', salt: 'bytes'});
_rtext.set(RecordType.NSEC3PARAM, (rdata: RDATA[RecordType.NSEC3PARAM])=>`${rdata.hash_algorithm} ${rdata.flags} ${rdata.iterations} ${rdata.salt.byteLength == 0 ? '-' : HexTxt(rdata.salt)}`);
_rdata.set(RecordType.TLSA, {cert_usage: 'u8', selector: 'u8', matching_type: 'u8', cert_assoc_data: 'opaque'});
_rtext.set(RecordType.TLSA, (rdata: RDATA[RecordType.TLSA])=>`${rdata.cert_usage} ${rdata.selector} ${rdata.matching_type} ${HexTxt(rdata.cert_assoc_data)}`);
_rdata.set(RecordType.SMIMEA, _rdata.get(RecordType.TLSA));
_rtext.set(RecordType.SMIMEA, _rtext.get(RecordType.TLSA));
_rdata.set(RecordType.HIP, 'opaque');
_rtext.set(RecordType.HIP, UnimplementedField);
_rdata.set(RecordType.NINFO, 'opaque');
_rtext.set(RecordType.NINFO, UnimplementedField);
_rdata.set(RecordType.RKEY, 'opaque');
_rtext.set(RecordType.RKEY, UnimplementedField);
_rdata.set(RecordType.TALINK, 'opaque');
_rtext.set(RecordType.TALINK, UnimplementedField);
_rdata.set(RecordType.CDS, _rdata.get(RecordType.DS));
_rtext.set(RecordType.CDS, _rtext.get(RecordType.DS));
_rdata.set(RecordType.CDNSKEY, _rdata.get(RecordType.DNSKEY));
_rtext.set(RecordType.CDNSKEY, _rtext.get(RecordType.DNSKEY));
_rdata.set(RecordType.OPENPGPKEY, 'opaque');
_rtext.set(RecordType.OPENPGPKEY, base64_encode);
_rdata.set(RecordType.CSYNC, {
    SOA_serial: 'u32',
    reserved1: 'bit',
    reserved2: 'bit',
    reserved3: 'bit',
    reserved4: 'bit',
    reserved5: 'bit',
    reserved6: 'bit',
    reserved7: 'bit',
    reserved8: 'bit',
    reserved9: 'bit',
    reserved10: 'bit',
    reserved11: 'bit',
    reserved12: 'bit',
    reserved13: 'bit',
    reserved14: 'bit',
    soaminimum: 'bit',
    immediate: 'bit',
    type_bit_map
});
_rtext.set(RecordType.CSYNC, (rdata: RDATA[RecordType.CSYNC])=>`${rdata.SOA_serial} ${(rdata.soaminimum ? 2 : 0) + (rdata.immediate ? 1 : 0)} ${TYPEBitmapTxt(rdata.type_bit_map)}`);
_rdata.set(RecordType.ZONEMD, 'opaque');
_rtext.set(RecordType.ZONEMD, UnimplementedField);
_rdata.set(RecordType.SVCB, {
    priority: 'u16', domainname: DOMAINNAME, values: (d: Tokenizer) => {
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
    }
});
_rtext.set(RecordType.SVCB, (rdata: RDATA[RecordType.SVCB])=>`${rdata.priority} ${DOMAINNAMETxt(rdata.domainname)} ${Object.entries(rdata.values).map(e=>e.join('=')).join(' ')}`);
_rdata.set(RecordType.HTTPSSVC, _rdata.get(RecordType.SVCB));
_rtext.set(RecordType.HTTPSSVC, _rtext.get(RecordType.SVCB));
_rdata.set(RecordType.SPF, 'string[]');
_rtext.set(RecordType.SPF, _rtext.get(RecordType.TXT));
_rdata.set(RecordType.UINFO, 'opaque');
_rtext.set(RecordType.UINFO, UnimplementedField);
_rdata.set(RecordType.UID, 'opaque');
_rtext.set(RecordType.UID, UnimplementedField);
_rdata.set(RecordType.GID, 'opaque');
_rtext.set(RecordType.GID, UnimplementedField);
_rdata.set(RecordType.UNSPEC, 'opaque');
_rtext.set(RecordType.UNSPEC, UnimplementedField);
_rdata.set(RecordType.NID, 'opaque');
_rtext.set(RecordType.NID, UnimplementedField);
_rdata.set(RecordType.L32, 'opaque');
_rtext.set(RecordType.L32, UnimplementedField);
_rdata.set(RecordType.L64, 'opaque');
_rtext.set(RecordType.L64, UnimplementedField);
_rdata.set(RecordType.LP, 'opaque');
_rtext.set(RecordType.LP, UnimplementedField);
_rdata.set(RecordType.EUI48, (d: Tokenizer) => (new Array(6)).fill(undefined).map(() => d.next('u8').value as number));
_rtext.set(RecordType.EUI48, (rdata: RDATA[RecordType.EUI48])=>rdata.map(v=>v.toString(16).padStart(2, '0')).join('-'));
_rdata.set(RecordType.EUI64, (d: Tokenizer) => (new Array(8)).fill(undefined).map(() => d.next('u8').value as number));
_rtext.set(RecordType.EUI64, _rtext.get(RecordType.EUI48));
_rdata.set(RecordType.TSIG, {
    algorithm_name: DOMAINNAME,
    time_signed: 'u48',
    fudge: 'u16',
    MAC: (d: Tokenizer) => (new Array(d.next('u16').value as number)).fill(undefined).map(() => d.next('u8').value as number),
    original_id: 'u16',
    error: 'u16',
    other_len: 'u16',
    other_data: 'opaque'
});
_rtext.set(RecordType.TSIG, (rdata: RDATA[RecordType.TSIG])=>`${DOMAINNAMETxt(rdata.algorithm_name)} ${rdata.time_signed} ${rdata.fudge} ${base64_encode(new Uint8Array(rdata.MAC).buffer)} ${rdata.original_id} ${rdata.error} ${base64_encode(rdata.other_data)}` + WIPWarningMessage);
// Not RR types
// rdata.set(RecordType.IXFR, 'opaque');
// rdata.set(RecordType.AXFR, 'opaque');
// rdata.set(RecordType.MAILB, 'opaque');
// rdata.set(RecordType.MAILA, 'opaque');
// rdata.set(RecordType['*'], 'opaque');
_rdata.set(RecordType.URI, {priority: 'u16', weight: 'u16', target: 'string[*]'});
_rtext.set(RecordType.URI, (rdata: RDATA[RecordType.URI])=>`${rdata.priority} ${rdata.weight} "${rdata.target}"`);
_rdata.set(RecordType.CAA, {issuer_critical: 'bit', reserved1: 'bit', reserved2: 'bit', reserved3: 'bit', reserved4: 'bit', reserved5: 'bit', reserved6: 'bit', reserved7: 'bit', tag: 'string', value: 'string[*]'});
_rtext.set(RecordType.CAA, (rdata: RDATA[RecordType.CAA])=>`${rdata.issuer_critical ? 1 << 7 : 0} ${rdata.tag} "${rdata.value}"`);
_rdata.set(RecordType.AVC, 'opaque');
_rtext.set(RecordType.AVC, UnimplementedField);
_rdata.set(RecordType.DOA, 'opaque');
_rtext.set(RecordType.DOA, UnimplementedField);
_rdata.set(RecordType.AMTRELAY, 'opaque');
_rtext.set(RecordType.AMTRELAY, UnimplementedField);
_rdata.set(RecordType.TA, 'opaque');
_rtext.set(RecordType.TA, UnimplementedField);
_rdata.set(RecordType.DLV, 'opaque');
_rtext.set(RecordType.DLV, UnimplementedField);

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
            return Object.entries(layout).reduce((acc, [k, v]) => {
                acc[k] = parseToken(d, v);
                return acc;
            }, {} as { [key: string]: any });
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

/**
 * Convert Resource Record RDATA to the specified presentation format
 * This may emit strings that contain a comment suffix delineated by a ';' character
 * @param rdata RR RDATA value
 * @param type RecordType of RDATA
 */
export function presentationFormat(rdata: RDATA[keyof RDATA], type: RecordType): string {
    return _rtext.get(type)(rdata);
}
