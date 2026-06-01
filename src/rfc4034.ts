// Attempt to grab a handle on the original browser supplied function to help mitigate XSS hijacking and injecting
// fake DNSSEC data. This can be easily countered by having the XSS attack occur earlier than this script is loaded.
const _fetch = fetch;
const _digest = crypto.subtle.digest.bind(crypto.subtle);
const _verify = crypto.subtle.verify.bind(crypto.subtle);
const _importKey = crypto.subtle.importKey.bind(crypto.subtle);
const _now = Date.now;
const _parseInt = parseInt;
// TODO are the following still hackable via Class.prototype? Should we optionally proxy a WebWorker via validate()?
const _fromUint8Array = Uint8Array.from.bind(Uint8Array);
const _Uint8Array = Uint8Array;
const _ArrayBuffer = ArrayBuffer;
if (typeof window === 'undefined') { // @ts-ignore
    // Allows importing in a nodejs script
    global.DOMParser = {prototype: {parseFromString: undefined}}
}
const _DOMParser = DOMParser;
const _Map = Map;
const parseXMLFromString = DOMParser.prototype.parseFromString;

import {DNSResponse, domainNameLen, Question, record, ResponseRecord,} from "./rfc1035.js";
import {serialize, TokenType} from "./bin_util.js";
import {ALGORITHMS, CLASS, DIGESTS, RecordType} from "./constants.js";
import {_rdata, DOMAINNAME, domainNameEq, RDATA} from "./rfc_rdata.js"
import {BaseResolver} from "./base_resolver.js";
import {base64url_encode} from "./base64url.js";
import {JsonWebKey} from "crypto";

/* TODO what is stopping a parent zone from signing a SOA of a child zone that states that the parent is actually the apex
 zone for the domain and subdomains? This parent zone can then serve this via a "bad-actor" DNS server. Once that is
 done then clients looking to validate the DNS chain will accept RRSIG from the parent zone for subdomains. The SOA
 describes where to look for DNSKEY to validate the RRSIG. Even if the client attempts to directly request SOA from a
 child zone, the bad actor DNS server can prevent it from reaching it and issue NSEC signed by the parent zone.
 You potentially dont even need a bad actor DNS given that all DNS need to traverse from the root while looking up NS.
 A request for the child zones NS can be omitted by the parent and the parent can freely publish records for the child
 zone that DNS servers would then proxy.
 */

// RRSIG - Contains a cryptographic signature signed by ZSK
// DNSKEY - Contains a public signing key. KSK or ZSK with zone_key flag set
// DS - Contains the hash of a DNSKEY record, RRSIG for this record is signed by parent zone ZSK. Hosted by parent zone, but lookup is done on child zone.
// NSEC and NSEC3 - For explicit denial-of-existence of a DNS record
// CDNSKEY and CDS - For a child zone requesting updates to DS record(s) in the parent zone.

const NSECTYPES = [RecordType.NSEC, RecordType.NSEC3];

type Expires = {
    expires: number
}

type CachedDS = (RDATA[RecordType.DS] & Expires)[];

type CachedCryptoKeys = Expires & {
    keys: CryptoKey[], keyTags: number[],
}

type ZoneResult = { name: DOMAINNAME, isZone: boolean, expires: number };

type CachedNSEC3PARAMS = RDATA[RecordType.NSEC3PARAM] & Expires;

// The following should be protected by the JS engine from any external code trying to inject values
let ROOTDIGESTS: CachedDS = [];
const SESSIONDSCACHE: Map<string, CachedDS> = new _Map<string, CachedDS>();
const SESSIONKEYCACHE: Map<string, CachedCryptoKeys> = new _Map<string, CachedCryptoKeys>();
const SESSIONZONECACHE: Map<string, ZoneResult> = new _Map<string, ZoneResult>();
const SESSIONNSEC3PARAMSCACHE: Map<string, CachedNSEC3PARAMS> = new _Map<string, CachedNSEC3PARAMS>();
const NSECNAMEDIGESTCACHE = new Map<string, ArrayBuffer>();

/**
 * Clear the internal session cache storing DNSSEC data that is fetched as part of validation
 */
export function clearCaches() {
    ROOTDIGESTS = [];
    SESSIONDSCACHE.clear();
    SESSIONKEYCACHE.clear();
    SESSIONZONECACHE.clear();
    SESSIONNSEC3PARAMSCACHE.clear();
    NSECNAMEDIGESTCACHE.clear();
}

/**
 * DNSSECValidationError is thrown when invalid DNSSEC data or state is encountered
 * This is not thrown when a response fails to validate with otherwise consistent DNSSEC data
 */
export class DNSSECValidationError extends Error {
    constructor(reason?: string) {
        reason = reason ? ": " + reason : "";
        super("DNSSEC Validation failed" + reason);
    }
}

/**
 * Get zone signing keys for owner zone
 * @param owner name of DNSKEYs
 * @param resolver An instance of a resolver used to make requests for the DNSKEY records
 * @param keyTag key tag of original DNSKEY to filter on
 */
// This function must not be exported as it returns a reference to the CryptoKeys and not a copy
async function getKeys(owner: DOMAINNAME, resolver: BaseResolver, keyTag?: number): Promise<CryptoKey[]> {
    const now = _now();
    const label = owner.join('.').toLowerCase();

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
    const response = (await resolver.resolve(label, 'DNSKEY', {
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
async function getStoredDS(owner: DOMAINNAME, resolver: BaseResolver): Promise<RDATA[RecordType.DS][]> {
    const dsOverride = resolver.getDSOverride(owner);
    if (dsOverride) return dsOverride;
    if (owner.length === 1 && owner[0].length === 0) return getRootDS();  // Root key

    // Check session cache
    const now = _now();
    const label = owner.join('.').toLowerCase();
    if (SESSIONDSCACHE.has(label)) {
        const ds = SESSIONDSCACHE.get(label).filter(d => d.expires > now);
        SESSIONDSCACHE.set(label, ds);
        if (ds.length) return ds;
    }

    // Fetch DS from DNS
    const response = await resolver.resolve(label, "DS", {
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
 * @param dsOverride List of DS RDATA to use instead of fetched DS or any DS overrides configured in the resolver
 * @return True if a zone DS matches the KSK digest, false otherwise
 */
export async function validateKSK(ksk: ResponseRecord<RecordType.DNSKEY>, resolver: BaseResolver, dsOverride?: RDATA[RecordType.DS][]): Promise<boolean> {
    if (!ksk.RDATA.zone_key) return false;  // The DNSKEY RR referred to in the DS RR MUST be a DNSSEC zone key.
    if (!ksk.raw_rdata || ksk.raw_rdata.byteLength === 0) throw Error('KSK raw_rdata field not populated');
    if (ksk.RDATA.protocol !== 3) return false; // https://datatracker.ietf.org/doc/html/rfc4034#section-2.1.2
    const owner = ksk.NAME.map(v => v.toLowerCase());
    const ds = dsOverride || await getStoredDS(owner, resolver);

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
    try {
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
    } catch (e) {
        throw new Error(`Failed to import DNSKEY key_tag: ${rdata.key_tag} algorithm: ${rdata.algorithm}`, {cause: e});
    }
}

/**
 * Canonical count of DNS name labels as per RRSIG RDATA 'labels' field
 * @param name DNS name to count
 */
export function labelCount(name: DOMAINNAME): number {
    let ownerNameLen = name.length;
    // Root (".") has a Labels field value of 0 and
    // The value of the Labels field MUST NOT count either the wildcard label (if present)
    if (name[0] === '*') ownerNameLen--;
    // or the null (root) label that terminates the owner name
    if (name[name.length - 1] === '') ownerNameLen--;
    return ownerNameLen;
}

/**
 * Helper to count the number of matching labels starting at the root (right to left)
 */
export function matchingLabels(a: DOMAINNAME, b: DOMAINNAME): number {
    let longer, shorter;
    if (a.length > b.length) [longer, shorter] = [a, b];
    else [shorter, longer] = [a, b];
    return shorter.toReversed().reduce((count, label, i) => label === longer.at(-(i + 1)) ? count + 1 : count, 0)
}

/**
 * Recursively query each subdomain walking up the domain hierarchy until a matching SOA record is found
 * @param name DOMAINNAME to resolve the zone apex for
 * @param resolver BaseResolver used to resolve SOA records
 * @param recurse If true and no SOA is returned when querying the resolver, recursively request SOA for parent domains
 */
// This function must not be exported as it returns a reference to the ZoneResult rather than a copy
async function getZoneApex(name: DOMAINNAME, resolver: BaseResolver, recurse = false): Promise<ZoneResult> {
    const now = _now();
    const domain = name.join('.');
    let cachedzone = SESSIONZONECACHE.get(domain);
    if (cachedzone) {
        if (cachedzone.expires <= now) SESSIONZONECACHE.delete(domain);
        else return cachedzone;
    }
    const response = await resolver.resolve(name.join('.'), "SOA", {
        dnssec: true,
        raw: true,
        recursive: true
    }) as DNSResponse;
    const combinedRecords = [...response.answer, ...response.authority];  // Recursive response can return SOA in auth section
    const zones = combinedRecords.filter((r: ResponseRecord<RecordType.SOA>) => r.TYPE === RecordType.SOA);
    for (const zone of zones) {
        SESSIONZONECACHE.set(zone.NAME.join('.'), {name: zone.NAME, isZone: true, expires: (zone.TTL * 1000) + now});
    }
    cachedzone = SESSIONZONECACHE.get(domain);
    if (cachedzone) return cachedzone;
    if (zones.length) {
        // Zones were returned that didn't match the name exactly, return the longest (best) matching zone
        // There really should only ever be one SOA returned at a time but it is conceiveable that a resolver may return all SOA records recursively.
        let longestMatch = zones[0];
        let longestMatchLength = matchingLabels(longestMatch.NAME, name);
        for (const zone of zones) {
            const matchLength = matchingLabels(zone.NAME, name);
            if (longestMatchLength < matchLength) {
                longestMatch = zone;
                longestMatchLength = matchLength;
            }
        }
        return SESSIONZONECACHE.get(longestMatch.NAME.join('.'));
    }
    cachedzone = {name, isZone: false, expires: now + 300000};
    SESSIONZONECACHE.set(domain, cachedzone);
    if (recurse) return getZoneApex(name.slice(1), resolver);
    return cachedzone;
}

/**
 * Helper to determine if a domain is a zone apex
 * @param name Domain name to query
 * @param resolver Resolver instance used to make subsequent DNS requests to fetch SOA records
 * @return true if the domain has an associated SOA record
 */
export async function isZoneApex(name: DOMAINNAME, resolver: BaseResolver): Promise<boolean> {
    const apex = await getZoneApex(name, resolver, false);
    return apex.isZone && domainNameEq(name, apex.name);
}

/**
 * Helper to determine if a domain is within a zone
 * @param query Subdomain to check
 * @param zone DNS name of zone
 * @param resolver Resolver instance used to make subsequent DNS requests to fetch SOA records
 * @return true if the query domain belongs to the provided DNS zone
 */
export async function inZone(query: DOMAINNAME, zone: DOMAINNAME, resolver: BaseResolver): Promise<boolean> {
    // Check that query is a descendant of zone
    if (matchingLabels(zone, query) !== zone.length) return false;

    const apex = await getZoneApex(query, resolver, true);
    return apex.isZone && domainNameEq(apex.name, zone);
}

export function canonicalCompareLabels(a: DOMAINNAME, b: DOMAINNAME) {
    for (let i = 1; i <= Math.min(a.length, b.length); ++i) {
        // This uses JS string comparison and isn't comparing individual characters, ie '' < 'example'
        if (a.at(-i) < b.at(-i)) return -1;
        if (a.at(-i) > b.at(-i)) return 1;
    }
    return a.length - b.length;
}

/**
 * Sort record names based on canonical DNS name order
 * https://www.rfc-editor.org/rfc/rfc4034#section-6.1
 * @param names List of names
 * @return names, sorted and lowercased
 */
export function canonicalSortLabels(names: DOMAINNAME[]): DOMAINNAME[] {
    // For the purposes of DNS security, owner names are ordered by treating
    // individual labels as unsigned left-justified octet strings.  The
    // absence of a octet sorts before a zero value octet, and uppercase
    // US-ASCII letters are treated as if they were lowercase US-ASCII
    // letters.
    names = names.map(name => name.map(label => label.toLowerCase()));
    return names.sort(canonicalCompareLabels);
}

export function canonicalSortRecords(rr: ResponseRecord<any>[]) {
    return rr.map(r => [r.NAME.map(label => label.toLowerCase()), r] as [DOMAINNAME, ResponseRecord<any>])
        .sort((pair1, pair2) => canonicalCompareLabels(pair1[0], pair2[0]))
        .map(pair => pair[1]);
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
    for (const [field, type] of Object.entries(_rdata.get(RecordType.RRSIG) as Record<keyof RDATA[RecordType.RRSIG], TokenType>)) {
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
                    val = (val as DOMAINNAME).map(v => v.toLowerCase());
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
 * @return true if the provided records are valid relative to the included RRSIG records
 * @throws DNSSECValidationError when some required relationship between the records, the DNSKEYs, and the RRSIGs is not met
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

    // Catch possible NSEC issue early
    const types_validating = new Set(rrsets.map(rrset => rrset[0].TYPE));
    if (!rrsigs.every(sig => types_validating.has(sig.RDATA.type_covered)))
        throw new DNSSECValidationError('RRSigs are present that cover RR types that are missing');

    const SOAIncluded = rrsets.findIndex(set => set[0].CLASS === CLASS.IN && set[0].TYPE === RecordType.SOA);
    if (SOAIncluded > 0) {
        // Move the SOA records first (second if there are DNSKEYs) in the list so they will be cached before validating other records
        const first = rrsets[0];
        rrsets[0] = rrsets[SOAIncluded];
        rrsets[SOAIncluded] = first;
    }

    // TODO sort DS ahead of others
    // DS MUST be included in the response: https://www.rfc-editor.org/rfc/rfc4035#section-3.1.4

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
        // RRSIG MUST be included in the response: https://www.rfc-editor.org/rfc/rfc4035#section-3.1.1
        const rrsigMatchResults = await Promise.all(rrsigs.map(async r =>
            r.NAME.join(".") === rr.NAME.join(".") &&  // The RRSIG RR and the RRset MUST have the same owner name
            r.CLASS === rr.CLASS &&  // and the same class.
            r.RDATA.type_covered === rr.TYPE &&  // The RRSIG RR's Type Covered field MUST equal the RRset's type.
            await inZone(rr.NAME, r.RDATA.signer, resolver) &&  // The RRSIG RR's Signer's Name field MUST be the name of the zone that contains the RRset.
            r.RDATA.labels <= labelCount(rr.NAME) &&  // The number of labels in the RRset owner name MUST be greater than or equal to the value in the RRSIG RR's Labels field.
            r.RDATA.sig_expiration >= now &&  // The validator's notion of the current time MUST be less than or equal to the time listed in the RRSIG RR's Expiration field.
            r.RDATA.sig_inception <= now  // The validator's notion of the current time MUST be greater than or equal to the time listed in the RRSIG RR's Inception field.
        ));
        const rrsigMatches = rrsigs.filter((_, i) => rrsigMatchResults[i]);

        if (!rrsigMatches || rrsigMatches.length === 0) throw new Error(`No matching RRSIG for ${rr.NAME.join('.')} ${RecordType[rr.TYPE]}`);
        // The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST match the owner name, algorithm, and key tag for some DNSKEY RR in the zone's apex DNSKEY RRset.
        // The matching DNSKEY RR MUST be present in the zone's apex DNSKEY RRset, and MUST have the Zone Flag bit (DNSKEY RDATA Flag bit 7) set.
        for (const rrsig of rrsigMatches) {
            if (rr.TYPE === RecordType.DNSKEY) {
                // Cache KSK
                const ksk = rrset.find(r => r.RDATA.key_tag === rrsig.RDATA.key_tag && r.RDATA.zone_key);
                if (ksk) {
                    if (!await validateKSK(ksk, resolver)) throw new DNSSECValidationError('Unable to validate KSK while verifying DNSKEYs');
                    // Verify rrset with KSK
                    const keys = [await importDNSKEY(ksk.RDATA)];
                    // Cache for later
                    const label = rr.NAME.join('.');
                    const expires = _now() + (ksk.TTL * 1000);
                    const key_tag = (ksk.RDATA as RDATA[RecordType.DNSKEY]).key_tag;
                    if (!SESSIONKEYCACHE.has(label)) {
                        SESSIONKEYCACHE.set(label, {
                            keys,
                            keyTags: [key_tag],
                            expires
                        });
                    } else {
                        const cache = SESSIONKEYCACHE.get(label);
                        if (!cache.keyTags.includes(key_tag)) {
                            cache.keys.push(keys[0]);
                            cache.keyTags.push(key_tag);
                            if (cache.expires > expires) cache.expires = expires;
                        }
                    }
                }
            }
            // The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST match the owner name, algorithm, and key tag for some DNSKEY RR in the zone's apex DNSKEY RRset.
            const keys = await getKeys(rrsig.RDATA.signer, resolver, rrsig.RDATA.key_tag);
            if (!keys || keys.length === 0) throw new Error('Unable to validate RRSIG, no valid signing key');
            if (await verifyRRSIG(keys, rrsig.RDATA, rrset)) continue match;
        }
        return false;
    }
    return true;
}

/**
 * Convert a DOMAINNAME to the format referred to by the relevant NSEC/NSEC3 records
 * @param rrName DOMAINNAME Domain name to reformat
 * @param zone DOMAINNAME Zone the rrName belongs to
 * @param nsec3params NSEC3PARAM RDATA used to hash rrName. If this is provided it is assumed that the NSEC3 scheme is requested, NSEC otherwise.
 */
export async function toNSECName(rrName: DOMAINNAME, zone: DOMAINNAME, nsec3params?: RDATA[RecordType.NSEC3PARAM]): Promise<DOMAINNAME> {
    if (!nsec3params) return rrName.map(label => label.toLowerCase());
    const dotName = rrName.join('.');
    let hashedName = NSECNAMEDIGESTCACHE.get(dotName);
    if (!hashedName) {
        const salt = new Uint8Array(nsec3params.salt);
        const nameWireFmt = new ArrayBuffer(domainNameLen(rrName) + salt.byteLength);
        const encoder = serialize(nameWireFmt);
        encoder.next();
        encoder.next(['string[]', rrName]);
        new Uint8Array(nameWireFmt).set(salt, nameWireFmt.byteLength - salt.byteLength);
        hashedName = await _digest(DIGESTS[nsec3params.hash_algorithm], nameWireFmt);
        for (let i = 1; i < nsec3params.iterations; ++i) {
            const concat = new Uint8Array(hashedName.byteLength + salt.byteLength);
            concat.set(new Uint8Array(hashedName));
            concat.set(salt, hashedName.byteLength);
            hashedName = await _digest(DIGESTS[nsec3params.hash_algorithm], concat);
        }
        NSECNAMEDIGESTCACHE.set(dotName, hashedName);
    }
    return [String.fromCodePoint(...new Uint8Array(hashedName)), ...zone.map(label => label.toLowerCase())];
}

/**
 * Test if a query domain name is within the canonical sorted range of the NSEC/NSEC3 record owner name and next owner name
 * @param nsec NSEC/NSEC3 record to test against
 * @param query Query domain name to check
 * @param zone Zone apex domain name for the Query/NSEC record
 */
export async function nsecCovers(nsec: ResponseRecord<RecordType.NSEC> | ResponseRecord<RecordType.NSEC3>, query: DOMAINNAME, zone: DOMAINNAME): Promise<boolean> {
    const before = nsec.NAME.map(label => label.toLowerCase());
    // Nowhere is it written but the NSEC3 hashes are determined by hashing the entire zones records and then produce NSEC3 records between the gaps in the HASH RANGE.
    // https://www.rfc-editor.org/rfc/rfc5155#section-5
    const after = nsec.TYPE === RecordType.NSEC3 ? [String.fromCodePoint(...new Uint8Array(nsec.RDATA.next_hashed_owner_name)), ...before.slice(1)] : nsec.RDATA.next_domain_name.map(label => label.toLowerCase());
    const q = await toNSECName(query, zone, nsec.TYPE === RecordType.NSEC3 ? nsec.RDATA as unknown as RDATA[RecordType.NSEC3PARAM] : undefined);
    return canonicalCompareLabels(before, q) <= 0 && canonicalCompareLabels(q, after) > 0;
}

/**
 * Validate DNS Response using included RRSIG records
 * The Question section of the response must be validated before calling this function
 * @param response DNS Response returned by Resolver
 * @param resolver Resolver instance used to make subsequent DNS requests needed to verify response
 */
export default async function validate(response: DNSResponse, resolver: BaseResolver) {
    if (!(await Promise.all([validateRecords(response.authority, resolver), validateRecords(response.additional, resolver), validateRecords(response.answer, resolver)])).every(x => x)) return false;

    // After validating all rrsets, check that all Questions have non-empty responses or NSEC records
    // https://datatracker.ietf.org/doc/html/rfc7129#page-12
    // NSEC records are only returned for the relevant range of the question
    // https://www.rfc-editor.org/rfc/rfc4035#section-5.4

    const rrsets = new Set(response.answer.map(rr => `${rr.NAME.join('.').toLowerCase()}_${rr.CLASS}_${rr.TYPE}`));
    const missing = response.question.filter(q=>!rrsets.has(`${q.QNAME.join('.').toLowerCase()}_${q.QCLASS}_${q.QTYPE}`));
    // The RRSIG signs the complete set of records for a given owner+class+type combination meaning that a partial response would not validate
    if (missing.length === 0) return true;  // All questions have been answered, no denial of existence check needed

    // Sort questions into the zone they should belong to
    const qZones = new Map<string, Question[]>();
    for (const q of missing) {
        const zone = await getZoneApex(q.QNAME, resolver, true);
        if (!zone.isZone) throw new DNSSECValidationError(`Unable to resolve zone for ${q.QNAME.join('.').toLowerCase()}`);
        const key = zone.name.join('.').toLowerCase();
        const bin = qZones.get(key) || [];
        bin.push(q);
        qZones.set(key, bin);
    }

    // NSEC MUST be returned by the resolver if relevant: https://www.rfc-editor.org/rfc/rfc4035#section-3.1.3
    // Though is it possible the resolver is non-compliant or the response is truncated
    const nsecZones = new Map<string, (ResponseRecord<RecordType.NSEC> | ResponseRecord<RecordType.NSEC3>)[]>();
    for (const nsec of [...response.answer, ...response.authority].filter(rr => NSECTYPES.includes(rr.TYPE)) as (ResponseRecord<RecordType.NSEC> | ResponseRecord<RecordType.NSEC3>)[]) {
        const zone = await getZoneApex(nsec.NAME, resolver, true);
        if (!zone.isZone) throw new DNSSECValidationError(`Unable to resolve zone for ${nsec.NAME.join('.').toLowerCase()}`);
        const key = zone.name.join('.').toLowerCase();
        const bin = nsecZones.get(key) || [];
        bin.push(nsec);
        nsecZones.set(key, bin);
    }

    for (const [z, questions] of qZones.entries()) {
        const zone = z.split('.');
        const nsecList = nsecZones.get(z) || [];
        for (const q of questions) {
            // Since a validated NSEC RR proves the existence of both itself and its corresponding RRSIG RR, a validator MUST
            // ignore the settings of the NSEC and RRSIG bits in an NSEC RR.
            // https://www.rfc-editor.org/rfc/rfc4035#section-5.4
            // Given that the requested NSEC is already determined to be missing, just fail
            if (NSECTYPES.includes(q.QTYPE)) return false;

            // If the requested RR name matches the owner name of an authenticated NSEC RR, then the NSEC RR's type bit map field lists all RR types present at that owner name, and a
            // resolver can prove that the requested RR type does not exist by checking for the RR type in the bit map.
            let nsec;
            let qname= q.QNAME;
            while (!nsec) {
                nsec = nsecList.find(nsec =>
                    // for a signed delegation (DS), there are two NSEC RRs associated with the delegated name.  One NSEC RR resides in the parent zone and
                    // can be used to prove whether a DS RRset exists for the delegated name.  The second NSEC RR resides in the child zone and identifies
                    // which RRsets are present at the apex of the child zone.  The parent NSEC RR and child NSEC RR can always be distinguished because the SOA
                    // bit will be set in the child NSEC RR and clear in the parent NSEC RR.
                    // A security-aware resolver MUST use the parent NSEC RR when attempting to prove that a DS RRset does not exist.
                    // https://www.rfc-editor.org/rfc/rfc4035#section-5.2
                    q.QTYPE === RecordType.DS && !nsec.RDATA.type_bit_map.has(RecordType.SOA) &&
                    nsecCovers(nsec, qname, zone)
                );
                if (!nsec) {
                    // At this point the only remaining questions are ones without answers or wildcard records. They must have a matching NSEC without the requested type bit set.
                    // Wildcard expansion needs to be accounted for when checking of a NSEC record.
                    if (qname.length <= zone.length) break;
                    qname = ['*', ...qname.slice(qname[0] === '*' ? 2 : 1)];
                }
            }

            if (nsec && !nsec.RDATA.type_bit_map.has(q.QTYPE)) continue;

            if (!nsec) {
                // If the complete set of necessary NSEC RRsets is not present in a response (perhaps due to message truncation),
                //  then a security-aware resolver MUST resend the query in order to attempt to obtain the full collection of NSEC
                //  RRs necessary to verify the non-existence of the requested RRset.  As with all DNS operations, however, the
                //  resolver MUST bound the work it puts into answering any particular query.
                // https://www.rfc-editor.org/rfc/rfc4035#section-5.4
                // This should trigger a re-attempt via the resolvers broader retry logic
                throw new DNSSECValidationError(`No NSEC/NSEC3 included in response for ${q.QNAME.join('.')} ${RecordType[q.QTYPE]}`);
            }

            // TODO verify NS sig opt-out for NSEC3. This may only apply if validation returns true for a zone without DNSSEC enabled. https://www.rfc-editor.org/rfc/rfc5155#section-6

            return false;
        }
    }
}
