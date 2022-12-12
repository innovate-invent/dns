import {CLASS, deserialize, record, Response, ResponseRecord, serialize} from "./rfc1035.js";
import parse, {_rdata, RDATA} from "./rfc_rdata.js"
import {BaseResolver} from "./base_resolver.js";
import {ALGORITHMS, RecordType} from "./constants.js";
import {base64url_decode, base64url_encode} from "./base64url.js";
import {JsonWebKey} from "crypto";
import CryptoKey = module;

// import * as crypto from "crypto";

// RRSIG - Contains a cryptographic signature signed by ZSK
// DNSKEY - Contains a public signing key. KSK or ZSK with zone_key flag set
// DS - Contains the hash of a DNSKEY record, RRSIG for this record is signed by parent zone ZSK. Hosted by parent zone, but lookup is done on child zone.
// NSEC and NSEC3 - For explicit denial-of-existence of a DNS record
// CDNSKEY and CDS - For a child zone requesting updates to DS record(s) in the parent zone.

type Expires = {
    expires: number
}

type Signed = {
    owner: string[],
    rrsig: {
        key_tag: number,
        algorithm: number,
        signer: string[],
        original_ttl: number,
        sig_expiration: number,
        sig_inception: number,
        signature: ArrayBuffer,
    }
}

type CachedDS = (RDATA[RecordType.DS] & Expires)[];

type StoredDS = {ds: CachedDS} & Signed;

type CachedCryptoKeys = Expires & {
    keys: CryptoKey[],
    keyTags: number[],
}

type StoredRRSET = Expires & {
    rdata: ArrayBuffer[],
    rrsig: ArrayBuffer,
}

type StoredDNSKEYs = StoredRRSET & {
    kskI: number,
}

// The following should be protected by the JS engine from any external code trying to inject values
let ROOTDIGESTS: CachedDS = [];
const SESSIONDSCACHE: Record<string, CachedDS> = {};
const SESSIONKEYCACHE: Record<string, CachedCryptoKeys> = {};

const STOREKEYPREFIX = "@i2labs.ca/dns/dnskey/"  // localStore key prefix for DNS Zone Keys
const STOREDSPREFIX = "@i2labs.ca/dns/ds/";  // localStore key prefix for DS records

/**
 * Get zone signing keys for owner zone
 * @param owner name of DNSKEY owner in canonical form (lowercase)
 * @param resolver An instance of a resolver used to make requests for the DNSKEY records
 * @param keyTag key tag of original DNSKEY to filter on
 */
async function getKeys(owner: string[], resolver: BaseResolver, keyTag?: number): Promise<CryptoKey[]> {
    const now = Date.now();
    const label = `${STOREKEYPREFIX}${owner.join('.')}`;

    // Check session cache
    if (label in SESSIONKEYCACHE) {
        const keys = SESSIONKEYCACHE[label];
        if (now >= keys.expires) {
            delete SESSIONKEYCACHE[label];
            return [];
        }
        if (keyTag !== undefined) return keys.keys.filter((k, i)=>keys.keyTags[i] === keyTag);
        return keys.keys;
    }

    // Check localStorage
    const s = localStorage.getItem(label);
    if (s) {
        const storedKeys: StoredDNSKEYs = JSON.parse(s);
        if (now >= storedKeys.expires) {
            localStorage.removeItem(label);
        } else {
            storedKeys.rdata = storedKeys.rdata.map(k=>base64url_decode(k as unknown as string));
            storedKeys.rrsig = base64url_decode(storedKeys.rrsig as unknown as string);
            const rrsigDecoder = deserialize(storedKeys.rrsig);
            rrsigDecoder.next();
            const rrsig = parse<RecordType.RRSIG>(rrsigDecoder, RecordType.RRSIG);
            const kskRDATA = storedKeys.rdata[storedKeys.kskI];
            const kskDecoder = deserialize(kskRDATA);
            kskDecoder.next();
            const kskParsed = parse<RecordType.DNSKEY>(kskDecoder, RecordType.DNSKEY);
            const ksk = await importDNSKEY(kskParsed);
            // TODO Find case there CLASS is not 'IN' and store the class in the serialized record https://serverfault.com/a/220784
            if (
                validateKSK({NAME: owner, RDATA: kskParsed, raw_rdata: kskRDATA} as ResponseRecord<RecordType.DNSKEY>, resolver) &&
                verifyRRSIG([ksk], rrsig, storedKeys.rdata.map(k=>({NAME: owner, TYPE: RecordType.DNSKEY, CLASS: CLASS.IN, RDLENGTH: k.byteLength, TTL: rrsig.original_ttl, raw_rdata: k})))
            ) {
                return storedKeys.rdata.filter((_, i)=>i !== storedKeys.kskI).map(k=>{

                })
            }
            // Validate KSK against DS
            // Reconstruct RRSIG from StoredCryptoKeys
            // Verify RRSIG using KSK
            // TODO
            const keys = await Promise.all(storedKeys.keys.map(async jwk => {
                return crypto.subtle.importKey("jwk", jwk as JsonWebKey, jwk.alg, true, jwk.key_ops as KeyUsage[]);
            }));

            if (await validateStoredKSK(owner, storedKeys.keyTags[storedKeys.kskI], keys[storedKeys.kskI], resolver)) {

            }
        }
    }

    // Retrieve keys
    const response = (await resolver.resolve(owner.join('.'), 'DNSKEY', {
        raw: true,
        dnssec: true
    }) as Response).answer;
    const keyResponse = response.filter(r => r.TYPE === RecordType.DNSKEY) as ResponseRecord<RecordType.DNSKEY>[];
    const rrsig = response.find(r => r.TYPE === RecordType.RRSIG) as ResponseRecord<RecordType.RRSIG>;
    const keys = await Promise.all(keyResponse.map(k=>importDNSKEY(k)));
    const kskI = keyResponse.findIndex(k=>k.RDATA.zone_key);
    const expires = (keyResponse.reduce((acc, cur)=>acc < cur.TTL ? acc : cur.TTL, 604800) * 1000) + now;  // Expires on lowest TTL + now
    const keyTags = keyResponse.map(k=>k.RDATA.key_tag);

    SESSIONKEYCACHE[label] = {
        keys,
        expires,
        keyTags,
    };
    localStorage.setItem(label, JSON.stringify({
        keys: (await Promise.all(keys.map(async key=>({alg: key.algorithm, ... await crypto.subtle.exportKey("jwk", key)} as StoredJWK)))),
        keyTags,
        kskI,
        expires,
        owner,
        rrsig: {
            key_tag: rrsig.RDATA.key_tag,
            algorithm: rrsig.RDATA.algorithm,
            original_ttl: rrsig.RDATA.original_ttl,
            sig_expiration: rrsig.RDATA.sig_expiration,
            sig_inception: rrsig.RDATA.sig_inception,
            signer: rrsig.RDATA.signer,
            signature: base64url_encode(rrsig.RDATA.signature) as unknown as ArrayBuffer,
        }
    } as StoredCryptoKeys));

    return keys.filter((_, i)=>i !== kskI);  // Do not include ksk
}

/**
 * Helper to retrieve IANA root anchor digests for validating DS chain.
 * This depends on the browsers HTTPS certificate validation to guarantee authenticity of root records.
 */
async function getRootDS(): Promise<typeof ROOTDIGESTS> {
    const now = Date.now();
    ROOTDIGESTS = ROOTDIGESTS.filter(d=>d.expires > now);
    if (ROOTDIGESTS) return ROOTDIGESTS;

    const response = await fetch("https://data.iana.org/root-anchors/root-anchors.xml");
    const anchor: XMLDocument = await response.text().then(t => new DOMParser().parseFromString(t, 'text/xml'));
    ROOTDIGESTS = [];
    anchor.querySelectorAll('KeyDigest').forEach(keydigest => {
        // https://www.rfc-editor.org/rfc/rfc7958.html
        // const id = keydigest.getAttribute("id");
        const validFrom = Date.parse(keydigest.getAttribute("validFrom"));
        const validUntil = keydigest.hasAttribute("validUntil") ? Date.parse(keydigest.getAttribute("validUntil")) : Date.parse(response.headers.get('expires'));
        if (validFrom <= now && now < validUntil) ROOTDIGESTS.push({
            expires: validUntil,
            key_tag: parseInt(keydigest.querySelector("KeyTag").textContent, 10),
            algorithm: parseInt(keydigest.querySelector("Algorithm").textContent, 10),
            digest_type: parseInt(keydigest.querySelector("DigestType").textContent, 10),
            digest: Uint8Array.from(keydigest.querySelector("DigestType").textContent.match(/../), c => parseInt(c, 16)).buffer,
        });
    });
    return ROOTDIGESTS;
}

/**
 * Fetch DS record for ksk from cache or request from resolver
 * @param owner KSK record to validate
 * @param resolver An instance of a resolver used to make requests for the DS records
 */
async function getStoredDS(owner: string[], resolver: BaseResolver): Promise<CachedDS> {
    if (owner.length === 1) return getRootDS();  // Root key

    // Check session cache
    const now = Date.now();
    const label = `${STOREDSPREFIX}${owner.join('.')}`;
    if (label in SESSIONDSCACHE) {
        const ds = SESSIONDSCACHE[label].filter(d=>d.expires > now);
        SESSIONDSCACHE[label] = ds;
        return ds;
    }

    // Check localStorage
    const s = localStorage.getItem(label);
    if (s) {
        const storedDS = JSON.parse(s) as StoredDS;
        storedDS.ds.forEach((d: RDATA[RecordType.DS]) => d.digest = base64url_decode(d.digest as unknown as string));
        storedDS.rrsig.signature = base64url_decode(storedDS.rrsig.signature as unknown as string);

        const keys = await getKeys(storedDS.rrsig.signer, resolver, storedDS.rrsig.key_tag);  // KSK of parent zone
        if (await validateStoredDS(keys, storedDS)) return storedDS.ds;
        throw new Error('No DS record for ' + owner);
    }

    // Fetch DS from DNS
    const response = await resolver.resolve(owner.join('.'), "DS", {
        raw: true,
        dnssec: true
    }) as Response;
    const dsrecords = response.answer.filter(r => r.TYPE === RecordType.DS) as ResponseRecord<RecordType.DS>[];
    if (!dsrecords) return [];
    const rrsig = response.answer.find(r => r.TYPE === RecordType.RRSIG && (r as ResponseRecord<RecordType.RRSIG>).RDATA.type_covered === RecordType.DS) as ResponseRecord<RecordType.RRSIG>;
    if (!rrsig) throw new Error('No RRSIG returned with DS');
    const dsset: Record<string, StoredDS> = {};

    for (const r of dsrecords) {
        const l = `${STOREDSPREFIX}${r.NAME.join('.')}`;
        const set = dsset[l] || {
            ds: [] as CachedDS,
            rrsig: {
                original_ttl: rrsig.RDATA.original_ttl,
                sig_expiration: rrsig.RDATA.sig_expiration,
                sig_inception: rrsig.RDATA.sig_inception,
                signer: rrsig.RDATA.signer,
                signature: rrsig.RDATA.signature
            }
        } as StoredDS;
        set.ds.push({
            ...r.RDATA,
            expires: (r.TTL * 1000) + now,
        });
        dsset[l] = set;
    }
    Object.entries(dsset).forEach(([k, v]: [string, StoredDS]) =>
        localStorage.setItem(k, JSON.stringify({
            ...v,
            ds: v.ds.map(d => ({...d, digest: base64url_encode(d.digest)})),
            rrsig: {...v.rrsig, signature: base64url_encode(v.rrsig.signature)}
        }))
    );
    return dsset[label].ds;
}

/**
 * Validate a StoredDS record with its signing key
 * @param keys Array of keys used to sign DS records
 * @param ds StoredDS record instance to validate
 */
async function validateStoredDS(keys: CryptoKey[], ds: StoredDS): Promise<boolean> {
    // Reconstruct rrsig and ds rrset
    const rrsigRDATA: RDATA[RecordType.RRSIG] = {
        type_covered: RecordType.DS,
        labels: ds.owner.length-1,
        ...ds.rrsig,
    };
    // {key_tag: 'u16', algorithm: 'u8', digest_type: 'u8', digest: 'opaque'}
    const rrset: ResponseRecord<RecordType.DS>[] = ds.ds.map(d=>{
        const buffer = new ArrayBuffer(4 + d.digest.byteLength);
        const encoder = serialize(buffer);
        encoder.next();
        for (const [label, type] of Object.entries(_rdata.get(RecordType.DS))) {
            encoder.next([type, d[label as keyof RDATA[RecordType.DS]]]);
        }
        return {
            NAME: ds.owner,
            TYPE: RecordType.DS,
            CLASS: CLASS.IN,
            RDLENGTH: buffer.byteLength,
            raw_rdata: buffer,
        } as ResponseRecord<RecordType.DS>;
    });
    return verifyRRSIG(keys, rrsigRDATA, rrset);
}

async function keyToRDATA(key: CryptoKey, owner: string[], protocol: number, algorithm: number): Promise<ArrayBuffer> {
    const pubkey = new Uint8Array(await crypto.subtle.exportKey("raw", key));

    const data = new ArrayBuffer(4 + pubkey.byteLength + owner.length + owner.reduce((acc, cur)=>acc + cur.length, 0));
    const encoder = serialize(data);
    encoder.next();
    encoder.next(['string[]', owner.map(v=>v.toLowerCase())]);
    encoder.next(['u8', 1]);
    encoder.next(['u8', 1]);
    encoder.next(['u8', protocol]);
    encoder.next(['u8', algorithm]);
    encoder.next(['opaque', pubkey]);

    return data;
}

async function validateStoredDNSKEYS(ksk: CryptoKey, keys: StoredCryptoKeys): Promise<boolean> {
    // Reconstruct rrsig and DNSKEY rrset
    const rrsigRDATA: RDATA[RecordType.RRSIG] = {
        type_covered: RecordType.DNSKEY,
        labels: keys.owner.length-1,
        ...keys.rrsig,
    };

    const rrsetRDATA = await Promise.all(keys.keys.map(k=>keyToRDATA(k, owner, protocol, algorithm)));

    const rrset: ResponseRecord<RecordType.DNSKEY>[] = rrsetRDATA.map(rdata=>{
        return {
            NAME: owner,
            TYPE: RecordType.DNSKEY,
            CLASS: CLASS.IN,
            RDLENGTH: rdata.byteLength,
            raw_rdata: rdata,
        } as ResponseRecord<RecordType.DNSKEY>;
    });
    return verifyRRSIG([ksk], rrsigRDATA, rrset);
}

/**
 * Validate a provided Key Signing Key by looking up the respective DS record and comparing the digest.
 * DS records are cached in localStorage, and revalidated when read from storage to protect from injection attacks.
 * @param ksk KSK record to validate. Requires NAME, RDATA, and raw_data fields populated.
 * @param resolver An instance of a resolver used to make requests for the DS records
 */
export async function validateKSK(ksk: ResponseRecord<RecordType.DNSKEY>, resolver: BaseResolver): Promise<boolean> {
    if (!ksk.RDATA.zone_key) return false;  // The DNSKEY RR referred to in the DS RR MUST be a DNSSEC zone key.
    const ds = await getStoredDS(ksk.NAME, resolver);

    // digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
    // DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.  "|" denotes concatenation
    const data = new ArrayBuffer(ksk.raw_rdata.byteLength + ksk.NAME.length + ksk.NAME.reduce((acc, cur)=>acc + cur.length, 0));
    const encoder = serialize(data);
    encoder.next();
    encoder.next(['string[]', ksk.NAME.map(v=>v.toLowerCase())]);
    encoder.next(['opaque', new Uint8Array(ksk.raw_rdata)]);

    for (const d of ds) {  // Find matching DS
        if (d.key_tag === ksk.RDATA.key_tag &&
            d.algorithm === ksk.RDATA.algorithm &&
            d.digest === await crypto.subtle.digest(ALGORITHMS[d.digest_type], data)
        ) return true;
    }
    return false;
}

async function validateStoredKSK(owner: string[], keyTag: number, protocol: number, algorithm: number, ksk: CryptoKey, resolver: BaseResolver): Promise<boolean> {
    const ds = await getStoredDS(owner, resolver);
    const data = await keyToRDATA(ksk, owner, protocol, algorithm);

    for (const d of ds) {  // Find matching DS
        if (d.key_tag === keyTag &&
            d.algorithm === ksk.alg &&
            d.digest === await crypto.subtle.digest(ALGORITHMS[d.digest_type], data)
        ) return true;
    }
    return false;
}

/**
 * Import a DNSKEY record to a CryptoKey for use by crypto library
 * @param key DNSKEY record
 */
export async function importDNSKEY(rdata: RDATA[RecordType.DNSKEY]): Promise<CryptoKey> {
    const algorithm = ALGORITHMS[rdata.algorithm];
    switch (rdata.algorithm) {
        case 13:
        case 14:
            // EDCSA public key is only supported via jwk: https://github.com/diafygi/webcrypto-examples/issues/30
            const jwk: JsonWebKey = {
                kty: "EC",
                crv: (algorithm as EcKeyImportParams).namedCurve,
                x: base64url_encode(rdata.public_key.slice(0, rdata.public_key.byteLength/2)),
                y: base64url_encode(rdata.public_key.slice(rdata.public_key.byteLength/2)),
                ext: true,
            };
            return crypto.subtle.importKey("jwk", jwk, algorithm, true, ["verify"]);
        default:
            return crypto.subtle.importKey("raw", rdata.public_key, algorithm, true, ["verify"]);
    }
}

/**
 * Canonical count of DNS name labels as per RRSIG RDATA 'labels' field
 * @param name DNS name to count
 */
export function labelCount(name: string[]): number {
    let ownerNameLen = name.length;
    // Root (".") has a Labels field value of 0 and
    // The value of the Labels field MUST NOT count either the wildcard label (if present)
    if (name[0] === '*' || name[0] === '') ownerNameLen--;
    // or the null (root) label that terminates the owner name
    if (name[name.length - 1] === '') ownerNameLen--;
    return ownerNameLen;
}

/**
 * Verify the rrset matches the RRSIG record signed with one of keys
 * @param keys Array of candidate keys, multiple can be attempted in the event that the signing key is ambiguous
 * @param rrsigRDATA RDATA for RRSIG record of rrset
 * @param rrset Array of ResponseRecords of same type returned in a single request. Must have raw_rdata field populated.
 */
export async function verifyRRSIG(keys: CryptoKey[], rrsigRDATA: RDATA[RecordType.RRSIG], rrset: ResponseRecord<any>[]): Promise<boolean> {
    if (!(rrsigRDATA.algorithm in ALGORITHMS)) throw new Error("Unable to verify rrsig, unsupported algorithm " + rrsigRDATA.algorithm);
    const data = signedData(rrsigRDATA, rrset);
    return Promise.any(keys.map(key=>crypto.subtle.verify(ALGORITHMS[rrsigRDATA.algorithm], key, rrsigRDATA.signature, data)));
}

/**
 * Construct the data represented by the RRSIG signature
 * @param rrsigRDATA RRSIG record RDATA, excluding signature
 * @param rrset Array of ResponseRecords signed by RRSIG. Must have raw_rdata field populated.
 * @return Buffer of data in canonical format ready to be cryptographically signed
 */
export function signedData(rrsigRDATA: RDATA[RecordType.RRSIG], rrset: ResponseRecord<any>[]): ArrayBuffer {
    // signed_data = RRSIG_RDATA | RR(1) | RR(2)...
    let bufferLen = 18 + rrsigRDATA.signer.reduce((acc, cur) => acc + cur.length, 0) + rrsigRDATA.signer.length;
    for (const rr of rrset) {
        bufferLen += rr.NAME.reduce((acc, cur) => acc + cur.length, 0) + rr.NAME.length;
        bufferLen += 10; // type | class | OrigTTL | RDATA length
        bufferLen += rr.raw_rdata.byteLength;
    }
    const data = new ArrayBuffer(bufferLen);
    const encoder = serialize(data);
    encoder.next();

    // RRSIG_RDATA is the wire format of the RRSIG RDATA fields with the Signature field excluded and the Signer's Name in canonical form.
    for (const [field, type] of Object.entries(_rdata.get(RecordType.RRSIG))) {
        if (field === "signer") {
            encoder.next([type, rrsigRDATA.signer.map(v => v.toLowerCase())]);
        } else if (field !== "signature") {
            encoder.next([type, rrsigRDATA[field as keyof RDATA[RecordType.RRSIG]]]);
        }
    }

    // RR(i) = name | type | class | OrigTTL | RDATA length | RDATA
    // rrset sorted by treating the RDATA portion of the canonical form of each RR as a left-justified
    // unsigned octet sequence in which the absence of an octet sorts before a zero octet
    rrset = rrset.map((rr, i) => [i, new Uint8Array(rr.raw_rdata)] as [number, Uint8Array]).sort((a, b) => {
        const maxLen = Math.max(a[1].length, b[1].length);
        let ai: number;
        let bi: number;
        for (let i = 0; i < maxLen; ++i) {
            if (i >= a.length) ai = -1;
            else ai = a[1][i];
            if (i >= b.length) bi = -1;
            else bi = b[1][i];
            if (ai === bi) continue;
            return ai - bi;
        }
    }).map(([i, _]) => rrset[i]);
    for (const rr of rrset) {
        for (const [field, type] of Object.entries(record)) {
            let val = rr[field as keyof ResponseRecord<any>];
            switch (field) {
                case "NAME":
                    // all uppercase US-ASCII letters in the owner name of the RR are replaced by the corresponding lowercase US-ASCII letters
                    // let rrsig_labels = the value of the RRSIG Labels field
                    // let fqdn = RRset's fully qualified domain name in canonical form
                    // let fqdn_labels = Label count of the fqdn above.
                    // if rrsig_labels = fqdn_labels, name = fqdn
                    // if rrsig_labels < fqdn_labels, name = "*." | the rightmost rrsig_label labels of the fqdn
                    // if rrsig_labels > fqdn_labels the RRSIG RR did not pass the necessary validation checks and MUST NOT be used to authenticate this RRset.
                    if (rrsigRDATA.labels < val.length-1) val = ["*", ...val.slice(-(rrsigRDATA.labels+1))];
                    val = (val as string[]).map(v => v.toLowerCase());
                    break;
                case "TTL":
                    // the RR's TTL is set to its original value as it appears in the originating authoritative zone or the Original TTL field of the covering RRSIG RR.
                    val = rrsigRDATA.original_ttl;
                    break;
                default:
                    break;
            }
            encoder.next([type, val]);
        }
        // TODO if the type of the RR is NS, MD, MF, CNAME, SOA, MB, MG, MR, PTR,
        // HINFO, MINFO, MX, HINFO, RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX,
        // SRV, DNAME, A6, RRSIG, or NSEC, all uppercase US-ASCII letters in
        // the DNS names contained within the RDATA are replaced by the
        // corresponding lowercase US-ASCII letters
        // tslint:disable-next-line
        encoder.next(['opaque', new Uint8Array(rr.raw_rdata)]);
    }
    return data;
}

/**
 * Validate DNS Response using included RRSIG records
 * @param response DNS Response returned by Resolver
 * @param resolver Resolver instance used to make subsequent DNS requests needed to verify response
 */
export default async function validate(response: Response, resolver: BaseResolver) {
    const rrsigs = response.answer.filter(r => r.TYPE === RecordType.RRSIG) as ResponseRecord<RecordType.RRSIG>[];
    if (!rrsigs) throw new Error('Unable to validate DNSKEY, missing matching RRSIG');

    const now = Math.floor(Date.now() / 1000);

    // Split up rrset on NAME, CLASS, TYPE
    const rrsets = Array.from(response.answer.filter(r => r.TYPE !== RecordType.RRSIG).reduce((acc, rr) => {
        const key = `${rr.NAME}_${rr.CLASS}_${rr.TYPE}`;
        const bin = acc.get(key) || [];
        bin.push(rr);
        acc.set(key, bin);
        return acc;
    }, new Map<string, ResponseRecord<any>[]>()).values());

    return (await Promise.all(rrsets.map(async rrset => {
        const rr = rrset[0];
        // https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.1
        const rrsigMatches = rrsigs.filter(r =>
            r.NAME.join(".") === rr.NAME.join(".") &&  // The RRSIG RR and the RRset MUST have the same owner name
            r.CLASS === rr.CLASS &&  // and the same class.
            r.RDATA.type_covered === rr.TYPE &&  // The RRSIG RR's Type Covered field MUST equal the RRset's type.
            rr.NAME.join(".").endsWith(r.RDATA.signer.join(".")) &&  // The RRSIG RR's Signer's Name field MUST be the name of the zone that contains the RRset.
            r.RDATA.labels <= labelCount(rr.NAME) &&  // The number of labels in the RRset owner name MUST be greater than or equal to the value in the RRSIG RR's Labels field.
            r.RDATA.sig_expiration >= now &&  // The validator's notion of the current time MUST be less than or equal to the time listed in the RRSIG RR's Expiration field.
            r.RDATA.sig_inception <= now  // The validator's notion of the current time MUST be greater than or equal to the time listed in the RRSIG RR's Inception field.
        );
        // The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST match the owner name, algorithm, and key tag for some DNSKEY RR in the zone's apex DNSKEY RRset.
        // The matching DNSKEY RR MUST be present in the zone's apex DNSKEY RRset, and MUST have the Zone Flag bit (DNSKEY RDATA Flag bit 7) set.
        return Promise.any(rrsigMatches.map(rrsig=>{
            switch (rr.TYPE) { // TODO check rrset CLASS is valid here
                case RecordType.DNSKEY:
                    if (rr.NAME.length === 1) {  // Root DNSKEY
                        // TODO

                    }
                    const ksk = rrset.find(r => r.RDATA.key_tag === rrsig.RDATA.key_tag && r.RDATA.zone_key);
                    if (ksk === undefined) throw new Error('Unable to validate DNSKEY, missing matching KSK');
                    if (rr.NAME.join('.').endsWith(rrsig.RDATA.signer.join('.'))) throw new Error('Unable to validate DNSKEY, RRSIG signer mismatch');
                    if (!await validateKSK(ksk, resolver)) throw new Error('Unable to validate DNSKEY, Invalid KSK');
                    // Verify rrset with KSK
                    const key = await importDNSKEY(ksk);
                    return verifyRRSIG([key], rrsig.RDATA, rrset);
                case RecordType.DS:
                    // The DS record contains a digest of your DNSSEC Key Signing Key (KSK), and acts as a pointer to the next key in the chain of trust.
                    // tslint:disable-next-line
                    // debugger;
                    // break;
                default:
                    // The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST match the owner name, algorithm, and key tag for some DNSKEY RR in the zone's apex DNSKEY RRset.
                    const zsk = await getKeys(rrsig.NAME, resolver, rrsig.RDATA.key_tag);
                    if (!zsk) throw new Error('Unable to validate RRSIG, no valid ZSK');
                    return verifyRRSIG(zsk, rrsig.RDATA, rrset);
            }
        }));
    }))).every(x => x)
}
