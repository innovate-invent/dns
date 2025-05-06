// Attempt to grab a handle on the original browser supplied function to help mitigate XSS hijacking and injecting
// fake DNSSEC data. This can be easily countered by having the XSS attack occur earlier than this script is loaded.
const _fetch = fetch;
const _digest = crypto.subtle.digest.bind(crypto.subtle);
const _verify = crypto.subtle.verify.bind(crypto.subtle);
const _importKey = crypto.subtle.importKey.bind(crypto.subtle);
const _now = Date.now;
const _parseInt = parseInt;
// TODO are the following still hackable via Class.prototype?
const _fromUint8Array = Uint8Array.from.bind(Uint8Array);
const _Uint8Array = Uint8Array;
const _ArrayBuffer = ArrayBuffer;
const _DOMParser = DOMParser;
const _Map = Map;
const parseXMLFromString = DOMParser.prototype.parseFromString;

import {
    AuthorityRecord,
    CLASS,
    DNSResponse,
    Question,
    record,
    ResponseRecord,
    serialize,
} from "./rfc1035.js";
import {ALGORITHMS, DIGESTS, RecordType} from "./constants.js";
import {_rdata, DOMAINNAME, RDATA} from "./rfc_rdata.js"
import {BaseResolver} from "./base_resolver.js";
import {base64url_encode} from "./base64url.js";
import {JsonWebKey} from "crypto";

// RRSIG - Contains a cryptographic signature signed by ZSK
// DNSKEY - Contains a public signing key. KSK or ZSK with zone_key flag set
// DS - Contains the hash of a DNSKEY record, RRSIG for this record is signed by parent zone ZSK. Hosted by parent zone, but lookup is done on child zone.
// NSEC and NSEC3 - For explicit denial-of-existence of a DNS record
// CDNSKEY and CDS - For a child zone requesting updates to DS record(s) in the parent zone.

type Expires = {
    expires: number
}

type CachedDS = (RDATA[RecordType.DS] & Expires)[];

type CachedCryptoKeys = Expires & {
    keys: CryptoKey[], keyTags: number[],
}

// The following should be protected by the JS engine from any external code trying to inject values
let ROOTDIGESTS: CachedDS = [];
const SESSIONDSCACHE: Map<string, CachedDS> = new _Map<string, CachedDS>();
const SESSIONKEYCACHE: Map<string, CachedCryptoKeys> = new _Map<string, CachedCryptoKeys>();

export function clearCaches() {
    ROOTDIGESTS = [];
    SESSIONDSCACHE.clear();
    SESSIONKEYCACHE.clear();
}

export class DNSSECValidationError extends Error {
    constructor(reason?: string) {
        reason = reason ? ": " + reason : "";
        super("DNSSEC Validation failed" + reason);
    }
}

/**
 * Get zone signing keys for owner zone
 * @param owner name of DNSKEY owner in canonical form (lowercase)
 * @param resolver An instance of a resolver used to make requests for the DNSKEY records
 * @param keyTag key tag of original DNSKEY to filter on
 */
// This function must not be exported as it returns a reference to the CryptoKeys and not a copy
async function getKeys(owner: string[], resolver: BaseResolver, keyTag?: number): Promise<CryptoKey[]> {
    const now = _now();
    const label = owner.join('.');

    // Check session cache
    if (SESSIONKEYCACHE.has(label)) {
        // eslint-disable-next-line:no-shadowed-variable
        const keys = SESSIONKEYCACHE.get(label);
        if (now >= keys.expires) {
            SESSIONKEYCACHE.delete(label);
            return [];
        }
        if (keyTag !== undefined) return keys.keys.filter((_, i) => keys.keyTags[i] === keyTag);
        return keys.keys;
    }

    // Retrieve keys
    const response = (await resolver.resolve(owner.join('.'), 'DNSKEY', {
        raw: true, dnssec: true
    }) as DNSResponse).answer;
    const keyResponse = response.filter(r => r.TYPE === RecordType.DNSKEY && (r as ResponseRecord<RecordType.DNSKEY>).RDATA.zone_key) as ResponseRecord<RecordType.DNSKEY>[];
    const keys = await Promise.all(keyResponse.map(k => importDNSKEY(k.RDATA)));
    const keyTags = keyResponse.map(k => k.RDATA.key_tag);
    const kskI = keyResponse.findIndex(k => k.RDATA.secure_entry_point);
    const expires = (keyResponse.reduce((acc, cur) => acc < cur.TTL ? acc : cur.TTL, 604800) * 1000) + now;  // Expires on lowest TTL + now

    // Move KSK to end of list
    [keys[keys.length - 1], keys[kskI]] = [keys.at(kskI), keys.at(-1)];
    [keyTags[keys.length - 1], keyTags[kskI]] = [keyTags.at(kskI), keyTags.at(-1)];

    SESSIONKEYCACHE.set(label, {
        keys, expires, keyTags,
    });

    return keys.filter((_, i) => keyTag === undefined || keyTags[i] === keyTag);
}

/**
 * Helper to retrieve IANA root anchor digests for validating DS chain.
 * This depends on the browsers HTTPS certificate validation to guarantee authenticity of root records.
 */
// This function must not be exported as it returns a reference to the root digest cache and not a copy
async function getRootDS(): Promise<typeof ROOTDIGESTS> {
    const now = _now();
    ROOTDIGESTS = ROOTDIGESTS.filter(d => d.expires > now);
    if (ROOTDIGESTS.length > 0) return ROOTDIGESTS;

    let response: Awaited<ReturnType<typeof fetch>>;
    try {
        response = await _fetch("https://data.iana.org/root-anchors/root-anchors.xml");
    } catch (e) {
        // eslint-disable-next-line:no-console
        console.error("Unable to fetch Root Zone Trust Anchors", e);
        throw e;
    }
    const anchor: XMLDocument = await response.text().then((t: string) => parseXMLFromString.call(new _DOMParser(), t, 'text/xml'));
    const errorNode = anchor.querySelector("parsererror");
    if (errorNode) {
        // eslint-disable-next-line:no-console
        console.error(errorNode.outerHTML);
        throw new Error('Unable to parse Root Zone Trust Anchors');
    }
    const zone = anchor.querySelector("Zone").textContent;
    if (zone !== '.') {
        throw new Error('Unexpected zone when retrieving the Root Zone Trust Anchors: ' + zone);
    }
    ROOTDIGESTS = [];
    anchor.querySelectorAll('KeyDigest').forEach(keydigest => {
        // https://www.rfc-editor.org/rfc/rfc7958.html
        // const id = keydigest.getAttribute("id");
        const validFrom = Date.parse(keydigest.getAttribute("validFrom"));
        let validUntil = now + 259200000;  // arbitrary 3 days
        if (keydigest.hasAttribute("validUntil")) validUntil = Date.parse(keydigest.getAttribute("validUntil")); else if (response.headers.has('expires')) validUntil = Date.parse(response.headers.get('expires')); else if (response.headers.has('cache-control')) {
            // Given IANAs current http response, this is the code path that will be used. The others are just
            // future proofing
            const maxAgeMatch = response.headers.get('cache-control').match(/(?<=max-age=)\d+/);
            if (maxAgeMatch) {
                const maxAge = _parseInt(maxAgeMatch[0], 10);
                if (!Number.isNaN(maxAge)) validUntil = now + (maxAge * 1000);
            }
        }
        // TODO verify the optional public key against the digest?
        if (validFrom <= now && now < validUntil) ROOTDIGESTS.push({
            expires: validUntil,
            key_tag: _parseInt(keydigest.querySelector("KeyTag").textContent, 10),
            algorithm: _parseInt(keydigest.querySelector("Algorithm").textContent, 10),
            digest_type: _parseInt(keydigest.querySelector("DigestType").textContent, 10),
            digest: _fromUint8Array(keydigest.querySelector("Digest").textContent.match(/\w\w/g), (c: string) => _parseInt(c, 16)).buffer,
        });
    });
    return ROOTDIGESTS;
}

/**
 * Fetch DS record for ksk from session cache or request from resolver
 * @param owner KSK record to validate
 * @param resolver An instance of a resolver used to make requests for the DS records
 */
// This function must not be exported as it returns a reference to the CachedDS rather than a copy
async function getStoredDS(owner: string[], resolver: BaseResolver): Promise<CachedDS> {
    if (owner.length === 1 && owner[0].length === 0) return getRootDS();  // Root key

    // Check session cache
    const now = _now();
    const label = owner.join('.');
    if (SESSIONDSCACHE.has(label)) {
        const ds = SESSIONDSCACHE.get(label).filter(d => d.expires > now);
        SESSIONDSCACHE.set(label, ds);
        if (ds.length) return ds;
    }

    // Fetch DS from DNS
    const response = await resolver.resolve(owner.join('.'), "DS", {
        raw: true, dnssec: true
    }) as DNSResponse;
    const dsrecords = response.answer.filter(r => r.TYPE === RecordType.DS) as ResponseRecord<RecordType.DS>[];
    if (!dsrecords || dsrecords.length === 0) return [];

    for (const r of dsrecords) {
        const l = r.NAME.join('.');
        const set = SESSIONDSCACHE.get(l) || [];
        set.push({
            ...r.RDATA, expires: (r.TTL * 1000) + now,
        });
        SESSIONDSCACHE.set(l, set);
    }

    return SESSIONDSCACHE.get(label);
}

/**
 * Validate a provided Key Signing Key by looking up the respective DS record and comparing the digest.
 * DS records are cached in localStorage, and revalidated when read from storage to protect from injection attacks.
 * @param ksk KSK record to validate. Requires NAME, RDATA, and raw_data fields populated.
 * @param resolver An instance of a resolver used to make requests for the DS records
 */
export async function validateKSK(ksk: ResponseRecord<RecordType.DNSKEY>, resolver: BaseResolver): Promise<boolean> {
    if (!ksk.RDATA.zone_key) return false;  // The DNSKEY RR referred to in the DS RR MUST be a DNSSEC zone key.
    if (!ksk.raw_rdata || ksk.raw_rdata.byteLength === 0) throw Error('KSK raw_rdata field not populated');
    if (ksk.RDATA.protocol !== 3) return false; // https://datatracker.ietf.org/doc/html/rfc4034#section-2.1.2
    const owner = ksk.NAME.map(v => v.toLowerCase());
    const ds = await getStoredDS(owner, resolver);

    // digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
    // DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.  "|" denotes concatenation
    const data = new _ArrayBuffer(ksk.raw_rdata.byteLength + owner.length + owner.reduce((acc, cur) => acc + cur.length, 0));
    const encoder = serialize(data);
    encoder.next();
    encoder.next(['string[]', owner]);
    encoder.next(['opaque', ksk.raw_rdata]);

    const digests: Record<number, Uint8Array> = {};
    for (const d of ds) {  // Find matching DS
        if (d.key_tag === ksk.RDATA.key_tag && d.algorithm === ksk.RDATA.algorithm) {
            digests[d.digest_type] = digests[d.digest_type] || new _Uint8Array(await _digest(DIGESTS[d.digest_type], data));
            const queryDigest = digests[d.digest_type];
            const refDigest = new _Uint8Array(d.digest);
            if (refDigest.byteLength === queryDigest.byteLength && refDigest.every((v, i) => v === queryDigest[i])) return true;
        }
    }
    return false;
}

/**
 * Import a DNSKEY record to a CryptoKey for use by crypto library
 * @param rdata DNSKEY record RDATA
 */
export async function importDNSKEY(rdata: RDATA[RecordType.DNSKEY]): Promise<CryptoKey> {
    if (!(rdata.algorithm in ALGORITHMS)) throw new Error(`Key algorithm ${rdata.algorithm} not implemented`);
    const algorithm = ALGORITHMS[rdata.algorithm];
    switch (rdata.algorithm) {
        case 5:
        case 7:
            // eslint-disable-next-line:no-console
            console.warn('DNSKEY record uses insecure SHA1 algorithm');
        // fallthrough
        case 8:
        case 10:
            // https://datatracker.ietf.org/doc/html/rfc3110#section-2
            const data = new DataView(rdata.public_key);
            let eLen = data.getUint8(0);
            let offset = 1;
            if (eLen === 0) { // Handle two byte exponent length
                eLen = data.getUint16(offset);
                offset += 2;
            }
            const e = rdata.public_key.slice(offset, offset + eLen);  // Exponent
            const n = rdata.public_key.slice(offset + eLen);  // Modulus
            // https://stackoverflow.com/a/19030716
            // https://www.rfc-editor.org/rfc/rfc3279
            let spki;
            // Reconstruct key data in SPKI format for import
            // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#subjectpublickeyinfo
            // TODO why the extra 0 before the modulus?!
            if (n.byteLength > 128) {
                spki = new Uint8Array([0x30, 0x82, 0xFF, 0xFF, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0xFF, 0xFF, 0x00, 0x30, 0x82, 0xFF, 0xFF, 0x02, 0x82, 0xFF, 0xFF, 0, ...new Uint8Array(n), 0x02, e.byteLength, ...new Uint8Array(e)]).buffer;
                const v = new DataView(spki);
                v.setUint16(2, v.byteLength - 4);
                v.setUint16(21, v.byteLength - 23);
                v.setUint16(26, v.byteLength - 28);
                v.setUint16(30, n.byteLength + 1);
            } else {
                spki = new Uint8Array([0x30, 0x81, 0xFF, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0xFF, 0x00, 0x30, 0x81, 0xFF, 0x02, 0x81, n.byteLength + 1, 0, ...new Uint8Array(n), 0x02, e.byteLength, ...new Uint8Array(e)]).buffer;
                const v = new DataView(spki);
                v.setUint8(2, v.byteLength - 3);
                v.setUint8(20, v.byteLength - 21);
                v.setUint8(24, v.byteLength - 25);
            }

            return _importKey("spki", spki, algorithm, true, ["verify"]);
        case 13:
        case 14:
            // ECDSA public key is only supported via jwk: https://github.com/diafygi/webcrypto-examples/issues/30
            const jwk: JsonWebKey = {
                kty: "EC",  // https://datatracker.ietf.org/doc/html/rfc7518#section-6.1
                crv: (algorithm as EcKeyImportParams).namedCurve,
                x: base64url_encode(rdata.public_key.slice(0, rdata.public_key.byteLength / 2)),
                y: base64url_encode(rdata.public_key.slice(rdata.public_key.byteLength / 2)),
                ext: true,
            };
            return _importKey("jwk", jwk, algorithm, true, ["verify"]);
        default:
            throw new Error(`Key algorithm ${rdata.algorithm} not implemented`);
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
    if (name[0] === '*') ownerNameLen--;
    // or the null (root) label that terminates the owner name
    if (name[name.length - 1] === '') ownerNameLen--;
    return ownerNameLen;
}

/**
 * Helper to determine if a domain is within a zone
 * @param query Subdomain to check
 * @param zone Parent domain
 */
export function isSameOrSubDomain(query: DOMAINNAME, zone: DOMAINNAME): boolean {
    return zone.toReversed().every((label, i) => label === query.at(-(i + 1)));
}

/**
 * Sort record names based on canonical DNS name order
 * https://www.rfc-editor.org/rfc/rfc4034#section-6.1
 * @param names List of names
 * @return names, sorted and lowercased
 */
export function canonicalSortLabels(names: string[][]): string[][] {
    // For the purposes of DNS security, owner names are ordered by treating
    // individual labels as unsigned left-justified octet strings.  The
    // absence of a octet sorts before a zero value octet, and uppercase
    // US-ASCII letters are treated as if they were lowercase US-ASCII
    // letters.
    names = names.map(name => name.map(label => label.toLowerCase()));
    return names.sort((a, b) => {
        for (let i = 1; i <= Math.min(a.length, b.length); ++i) {
            // This uses JS string comparison and isn't comparing individual characters, ie '' < 'example'
            if (a.at(-i) < b.at(-i)) return -1;
            if (a.at(-i) > b.at(-i)) return 1;
        }
        return a.length - b.length;
    })
}

/**
 * Verify the rrset matches the RRSIG record signed with one of keys
 * @param keys Array of candidate keys, multiple can be attempted in the event that the signing key is ambiguous
 * @param rrsigRDATA RDATA for RRSIG record of rrset, the inception and expiration must already be validated
 * @param rrset Array of ResponseRecords of same type returned in a single request. Must have raw_rdata field populated.
 * @returns true if a key is found that validates the rrset against the rrsig, false otherwise
 */
export async function verifyRRSIG(keys: CryptoKey[], rrsigRDATA: RDATA[RecordType.RRSIG], rrset: ResponseRecord<any>[]): Promise<boolean> {
    if (!(rrsigRDATA.algorithm in ALGORITHMS)) throw new Error("Unable to verify rrsig, unsupported algorithm " + rrsigRDATA.algorithm);
    const data = signedData(rrsigRDATA, rrset);
    for (const key of keys) {
        if (await _verify(ALGORITHMS[rrsigRDATA.algorithm], key, rrsigRDATA.signature, data)) return true;
    }
    return false;
}

/**
 * Construct the data represented by the RRSIG signature
 * @param rrsigRDATA RRSIG record RDATA, excluding signature
 * @param rrset Array of ResponseRecords signed by RRSIG. Must all match type_covered. Must have raw_rdata field populated.
 * @return Buffer of data in canonical format ready to be cryptographically signed
 */
export function signedData(rrsigRDATA: RDATA[RecordType.RRSIG], rrset: ResponseRecord<any>[]): ArrayBuffer {
    // signed_data = RRSIG_RDATA | RR(1) | RR(2)...
    let bufferLen = 18 /* RRSIG fixed width field total size */ + rrsigRDATA.signer.reduce((acc, cur) => acc + cur.length, 0) + rrsigRDATA.signer.length;
    for (const rr of rrset) {
        if (rrsigRDATA.labels > rr.NAME.length - 1) throw new DNSSECValidationError(`${rr.NAME} ${RecordType[rr.TYPE]} is a higher level domain than the RRSIG validating it`);
        if (rrsigRDATA.type_covered !== rr.TYPE) throw new DNSSECValidationError(`${rr.NAME} ${RecordType[rr.TYPE]} does not match the RRSIG type covered (${RecordType[rrsigRDATA.type_covered]}) when building the signed data for comparison`);
        bufferLen += rr.NAME.slice(-(rrsigRDATA.labels + 1)).reduce((acc, cur) => acc + cur.length, 0);
        bufferLen += rrsigRDATA.labels + 1 + (rr.NAME.length > rrsigRDATA.labels + 1 ? 2 : 0); // Include length bytes
        bufferLen += 10; // type | class | OrigTTL | RDATA length
        bufferLen += rr.raw_rdata.byteLength;
    }
    const data = new ArrayBuffer(bufferLen);
    const encoder = serialize(data);
    encoder.next();

    // https://datatracker.ietf.org/doc/html/rfc4034#section-6.2
    // RRSIG_RDATA is the wire format of the RRSIG RDATA fields with the Signature field excluded and the Signer's Name in canonical form.
    for (const [field, type] of Object.entries(_rdata.get(RecordType.RRSIG))) {
        if (field === "signer") {
            if (rrsigRDATA.signer.at(-1) !== '') throw new Error('RRSIG Signer not well formed, missing terminating empty string');
            encoder.next([type, rrsigRDATA.signer.map(v => v.toLowerCase())]);
        } else if (field !== "signature") {
            encoder.next([type, rrsigRDATA[field as keyof RDATA[RecordType.RRSIG]]]);
        }
    }

    // https://datatracker.ietf.org/doc/html/rfc4034#section-6.3
    // RR(i) = name | type | class | OrigTTL | RDATA length | RDATA
    // rrset sorted by treating the RDATA portion of the canonical form of each RR as a left-justified
    // unsigned octet sequence in which the absence of an octet sorts before a zero octet
    rrset = rrset.map((rr, i) => [i, new Uint8Array(rr.raw_rdata)] as [number, Uint8Array]).sort((a, b) => {
        const maxLen = Math.max(a[1].length, b[1].length);
        let ai: number;
        let bi: number;
        for (let i = 0; i < maxLen; ++i) {
            if (i >= a.length) ai = -1; else ai = a[1][i];
            if (i >= b.length) bi = -1; else bi = b[1][i];
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
                    if (rrsigRDATA.labels > val.length - 1) throw new DNSSECValidationError(`${rr.NAME} ${RecordType[rr.TYPE]} is a higher level domain than the RRSIG validating it`);
                    if (rrsigRDATA.labels < val.length - 1) val = ["*", ...val.slice(-(rrsigRDATA.labels + 1))];
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
        // this is incomplete as we are currently using the pre-built raw_rdata rather than regenerating it
        encoder.next(['opaque', rr.raw_rdata]);
    }
    return data;
}

/**
 * Validate array of records against included RRSIGs
 * @param records Array of ResponseRecords including accompanying RRSIG
 * @param resolver Resolver instance used to make subsequent DNS requests needed to verify response
 * @throws Error when some required relationship between the records, the DNSKEYs, and the RRSIGs is not met
 */
export async function validateRecords(records: ResponseRecord<any>[], resolver: BaseResolver): Promise<boolean> {
    const rrsigs = records.filter(r => r.TYPE === RecordType.RRSIG) as ResponseRecord<RecordType.RRSIG>[];
    if (rrsigs.length === 0) throw new Error('Unable to validate records, no RRSIG records present');

    const now = Math.floor(_now() / 1000);

    // Split up rrset on NAME, CLASS, TYPE
    const rrsets = Array.from(records.filter(r => r.TYPE !== RecordType.RRSIG).reduce((acc, rr) => {
        const key = `${rr.NAME}_${rr.CLASS}_${rr.TYPE}`;
        const bin = acc.get(key) || [];
        bin.push(rr);
        acc.set(key, bin);
        return acc;
    }, new Map<string, ResponseRecord<any>[]>()).values());

    const keysIncluded = rrsets.findIndex(set => set[0].CLASS === CLASS.IN && set[0].TYPE === RecordType.DNSKEY && set.some((k: ResponseRecord<RecordType.DNSKEY>) => k.RDATA.zone_key));
    if (keysIncluded > 0) {
        // Move the DNSKEYs first in the list so they will be cached before validating other records
        const first = rrsets[0];
        rrsets[0] = rrsets[keysIncluded];
        rrsets[keysIncluded] = first;
    }

    match: for (const rrset of rrsets) {
        const rr = rrset[0];
        // https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.1
        const rrsigMatches = rrsigs.filter(r =>
            r.NAME.join(".") === rr.NAME.join(".") &&  // The RRSIG RR and the RRset MUST have the same owner name
            r.CLASS === rr.CLASS &&  // and the same class.
            r.RDATA.type_covered === rr.TYPE &&  // The RRSIG RR's Type Covered field MUST equal the RRset's type.
            isSameOrSubDomain(rr.NAME, r.RDATA.signer) &&  // The RRSIG RR's Signer's Name field MUST be the name of the zone that contains the RRset.
            r.RDATA.labels <= labelCount(rr.NAME) &&  // The number of labels in the RRset owner name MUST be greater than or equal to the value in the RRSIG RR's Labels field.
            r.RDATA.sig_expiration >= now &&  // The validator's notion of the current time MUST be less than or equal to the time listed in the RRSIG RR's Expiration field.
            r.RDATA.sig_inception <= now  // The validator's notion of the current time MUST be greater than or equal to the time listed in the RRSIG RR's Inception field.
        );

        if (!rrsigMatches || rrsigMatches.length === 0) throw new Error(`No matching RRSIG for ${rr.NAME.join('.')} ${RecordType[rr.TYPE]}`);
        // The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST match the owner name, algorithm, and key tag for some DNSKEY RR in the zone's apex DNSKEY RRset.
        // The matching DNSKEY RR MUST be present in the zone's apex DNSKEY RRset, and MUST have the Zone Flag bit (DNSKEY RDATA Flag bit 7) set.
        for (const rrsig of rrsigMatches) {
            let keys: CryptoKey[];
            if (rr.TYPE === RecordType.DNSKEY) {
                // Handle KSK
                const ksk = rrset.find(r => r.RDATA.key_tag === rrsig.RDATA.key_tag && r.RDATA.zone_key);
                if (ksk === undefined) throw new Error('Unable to validate DNSKEY, missing matching KSK'); // TODO if non-zone DNSKEY is at subdomain then KSK may not actually be included in response
                // TODO are subdomains valid?
                if (!isSameOrSubDomain(rr.NAME, rrsig.RDATA.signer)) throw new Error('Unable to validate DNSKEY, RRSIG signer mismatch');
                if (!await validateKSK(ksk, resolver)) throw new Error('Unable to validate DNSKEY, invalid KSK');
                // Verify rrset with KSK
                keys = [await importDNSKEY(ksk.RDATA)];
                // Cache for later
                const label = rr.NAME.join('.');
                const expires = _now() + (ksk.TTL * 1000);
                const key_tag = (ksk.RDATA as RDATA[RecordType.DNSKEY]).key_tag;
                if (!SESSIONKEYCACHE.has(label)) SESSIONKEYCACHE.set(label, {
                    keys,
                    keyTags: [key_tag],
                    expires
                });
                else {
                    const cache = SESSIONKEYCACHE.get(label);
                    if (!cache.keyTags.includes(key_tag)) {
                        cache.keys.push(keys[0]);
                        cache.keyTags.push(key_tag);
                        if (cache.expires > expires) cache.expires = expires;
                    }
                }
            } else {
                // The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST match the owner name, algorithm, and key tag for some DNSKEY RR in the zone's apex DNSKEY RRset.
                keys = await getKeys(rrsig.RDATA.signer, resolver, rrsig.RDATA.key_tag);
            }
            if (!keys || keys.length === 0) throw new Error('Unable to validate RRSIG, no valid signing key');
            if (await verifyRRSIG(keys, rrsig.RDATA, rrset)) continue match;
        }
        return false;
    }
    return true;
}

/**
 * Validate DNS Response using included RRSIG records
 * The Question section of the response must be validated before calling this function
 * @param response DNS Response returned by Resolver
 * @param resolver Resolver instance used to make subsequent DNS requests needed to verify response
 */
export default async function validate(response: DNSResponse, resolver: BaseResolver) {
    if (!(await Promise.all([validateRecords(response.answer, resolver), validateRecords(response.authority, resolver), validateRecords(response.additional, resolver)])).every(x => x)) return false;

    // After validating all rrsets, check that all Questions have non-empty responses or NSEC records
    // https://www.rfc-editor.org/rfc/rfc4035#section-5.4
    const questions = new Map<string, Question>(response.question.map(q => [q.QNAME.join(".").toLowerCase(), q]));
    const rrsets = new Set(response.answer.map(rr => `${rr.NAME.join(".").toLowerCase()}_${rr.CLASS}_${rr.TYPE}`));
    const nsecMap = new Map<string, AuthorityRecord<RecordType.NSEC> | AuthorityRecord<RecordType.NSEC3>>(response.authority.filter(rr => rr.TYPE === RecordType.NSEC || rr.TYPE === RecordType.NSEC3).map((rr: AuthorityRecord<RecordType.NSEC>) => [rr.NAME.join(".").toLowerCase(), rr]));
    const nsecSigs = new Map<string, AuthorityRecord<RecordType.RRSIG>>(response.authority.filter(rr => rr.TYPE === RecordType.RRSIG && (rr as ResponseRecord<RecordType.RRSIG>).RDATA.type_covered in [RecordType.NSEC, RecordType.NSEC3]).map((rr: AuthorityRecord<RecordType.RRSIG>) => [rr.NAME.join(".").toLowerCase(), rr]));
    const names = canonicalSortLabels([...Array.from(nsecMap.values()).map(n => n.NAME), ...response.question.map(q => q.QNAME)]).map(n => n.join("."));
    return true;
    //const nameDigests = new Map<string, ArrayBuffer>();
    //const soa = new Map<string, AuthorityRecord<RecordType.SOA>>(response.authority.filter(rr => rr.TYPE === RecordType.SOA).map((rr: AuthorityRecord<RecordType.SOA>) => [rr.NAME.join(".").toLowerCase(), rr]));
    for (const [name, q] of questions.entries()) {
        const qIndex = names.lastIndexOf(name);
        const nsecName = names.at(qIndex - 1);
        const nsec = nsecMap.get(nsecName);
        const sig = nsecSigs.get(nsecName);

        // Skip answered questions
        if (rrsets.has(`${name}_${q.QCLASS}_${q.QTYPE}`)) {
            // If the requested RR name matches the owner name of an authenticated NSEC RR, then the NSEC RR's type bit map field lists all RR types present at that owner name, and a
            // resolver can prove that the requested RR type does not exist by checking for the RR type in the bit map.
            if (!nsec || nsec.RDATA.type_bit_map.has(q.QTYPE)) continue;
            throw new Error(`NSEC bitmap does not match answer for ${name} ${q.QCLASS} ${q.QTYPE}`);  // TODO log and return false?
        }

        // At this point the only remaining questions are ones without answers or wildcard records. They must have a matching NSEC without the requested type bit set.
        // Wildcard expansion needs to be accounted for when checking of a NSEC record.

        // example.com NSEC *.example.com
        // *.example.com NSEC foo.example.com
        // foo.example.com NSEC example.com

        // TODO verify NS sig opt-out for NSEC3. This may only apply to upstream DNS Resolvers. https://www.rfc-editor.org/rfc/rfc5155#section-6


        // Denial of existence is determined by the following rules:
        if (sig.RDATA.labels === q.QNAME.length) {
            // If the number of labels in an authenticated NSEC RR's owner name equals the Labels field of the covering RRSIG RR, then the existence of the NSEC RR proves that
            // wildcard expansion could not have been used to match the request.
            if (!nsec.RDATA.type_bit_map.has(q.QTYPE)) continue;
        } else {
            // If the requested RR name would appear after an authenticated NSEC RR's owner name and before the name listed in that NSEC RR's Next Domain Name field according to the
            // canonical DNS name order defined in [RFC4034], then no RRsets with the requested name exist in the zone.

            // However, it is possible that a wildcard could be used to match the requested RR owner name and type, so proving that the requested RRset does not exist also requires
            // proving that no possible wildcard RRset exists that could have been used to generate a positive response.
            /*const originalName = ["*", ...q.QNAME.slice(-(sig.RDATA.labels + 1))].join(".");
             if ("next_domain_name" in nsec.RDATA) {
             const names = canonicalSortLabels([nsec.NAME, q.QNAME, nsec.RDATA.next_domain_name]).map(n=>n.join("."));

             } else {
             // NSEC3 hashed next_domain_name
             const dotName = nsec.NAME.join('.');
             let hashedName = nameDigests.get(dotName);
             if (!hashedName) {
             const salt = new Uint8Array(nsec.RDATA.salt);
             const nameWireFmt = new ArrayBuffer(domainNameLen(nsec.NAME) + salt.byteLength);
             const encoder = serialize(nameWireFmt);
             encoder.next();
             encoder.next(['string[]', nsec.NAME]);
             new Uint8Array(nameWireFmt).set(salt, nameWireFmt.byteLength - salt.byteLength);
             hashedName = await _digest(DIGESTS[nsec.RDATA.hash_algorithm], nameWireFmt);
             for (let i = 1; i < nsec.RDATA.iterations; ++i) {
             const concat = new Uint8Array(hashedName.byteLength + salt.byteLength);
             concat.set(new Uint8Array(hashedName));
             concat.set(salt, hashedName.byteLength);
             hashedName = await _digest(DIGESTS[nsec.RDATA.hash_algorithm], concat);
             }
             nameDigests.set(dotName, hashedName);
             }

             }*/

        }
        return false;
    }
}
