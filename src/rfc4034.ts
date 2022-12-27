import {record, Response, ResponseRecord, serialize} from "./rfc1035.js";
import {_rdata, RDATA} from "./rfc_rdata.js"
import {BaseResolver} from "./base_resolver.js";
import {ALGORITHMS, DIGESTS, RecordType} from "./constants.js";
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
    keys: CryptoKey[],
    keyTags: number[],
}

// The following should be protected by the JS engine from any external code trying to inject values
let ROOTDIGESTS: CachedDS = [];
const SESSIONDSCACHE: Record<string, CachedDS> = {};
const SESSIONKEYCACHE: Record<string, CachedCryptoKeys> = {};

/**
 * Get zone signing keys for owner zone
 * @param owner name of DNSKEY owner in canonical form (lowercase)
 * @param resolver An instance of a resolver used to make requests for the DNSKEY records
 * @param keyTag key tag of original DNSKEY to filter on
 */
async function getKeys(owner: string[], resolver: BaseResolver, keyTag?: number): Promise<CryptoKey[]> {
    const now = Date.now();
    const label = owner.join('.');

    // Check session cache
    if (label in SESSIONKEYCACHE) {
        // tslint:disable-next-line:no-shadowed-variable
        const keys = SESSIONKEYCACHE[label];
        if (now >= keys.expires) {
            delete SESSIONKEYCACHE[label];
            return [];
        }
        if (keyTag !== undefined) return keys.keys.filter((k, i)=>keys.keyTags[i] === keyTag);
        return keys.keys;
    }

    // Retrieve keys
    const response = (await resolver.resolve(owner.join('.'), 'DNSKEY', {
        raw: true,
        dnssec: true
    }) as Response).answer;
    const keyResponse = response.filter(r => r.TYPE === RecordType.DNSKEY) as ResponseRecord<RecordType.DNSKEY>[];
    const keys = await Promise.all(keyResponse.map(k=>importDNSKEY(k.RDATA)));
    const kskI = keyResponse.findIndex(k=>k.RDATA.zone_key);
    const expires = (keyResponse.reduce((acc, cur)=>acc < cur.TTL ? acc : cur.TTL, 604800) * 1000) + now;  // Expires on lowest TTL + now
    const keyTags = keyResponse.map(k=>k.RDATA.key_tag);

    SESSIONKEYCACHE[label] = {
        keys,
        expires,
        keyTags,
    };

    return keys.filter((_, i)=>i !== kskI);  // Do not include ksk
}

/**
 * Helper to retrieve IANA root anchor digests for validating DS chain.
 * This depends on the browsers HTTPS certificate validation to guarantee authenticity of root records.
 */
async function getRootDS(): Promise<typeof ROOTDIGESTS> {
    const now = Date.now();
    ROOTDIGESTS = ROOTDIGESTS.filter(d=>d.expires > now);
    if (ROOTDIGESTS.length > 0) return ROOTDIGESTS;

    let response: Awaited<ReturnType<typeof fetch>>;
    try {
        response = await fetch("https://iana.pages.dev/root-anchors.xml");
        // TODO response = await fetch("https://data.iana.org/root-anchors/root-anchors.xml");
    } catch (e) {
        // tslint:disable-next-line:no-console
        console.log("Unable to fetch Root Zone Trust Anchors", e);
        throw e;
    }
    const anchor: XMLDocument = await response.text().then((t: string) => new DOMParser().parseFromString(t, 'text/xml'));
    ROOTDIGESTS = [];
    anchor.querySelectorAll('KeyDigest').forEach(keydigest => {
        // https://www.rfc-editor.org/rfc/rfc7958.html
        // const id = keydigest.getAttribute("id");
        const validFrom = Date.parse(keydigest.getAttribute("validFrom"));
        let validUntil = now + 259200000;  // 3 days
        if (keydigest.hasAttribute("validUntil")) validUntil = Date.parse(keydigest.getAttribute("validUntil"));
        else if (response.headers.has('expires')) validUntil = Date.parse(response.headers.get('expires'));
        if (validFrom <= now && now < validUntil) ROOTDIGESTS.push({
            expires: validUntil,
            key_tag: parseInt(keydigest.querySelector("KeyTag").textContent, 10),
            algorithm: parseInt(keydigest.querySelector("Algorithm").textContent, 10),
            digest_type: parseInt(keydigest.querySelector("DigestType").textContent, 10),
            digest: Uint8Array.from(keydigest.querySelector("Digest").textContent.match(/../g), c => parseInt(c, 16)).buffer,
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
    const label = owner.join('.');
    if (label in SESSIONDSCACHE) {
        const ds = SESSIONDSCACHE[label].filter(d=>d.expires > now);
        SESSIONDSCACHE[label] = ds;
        return ds;
    }

    // Fetch DS from DNS
    const response = await resolver.resolve(owner.join('.'), "DS", {
        raw: true,
        dnssec: true
    }) as Response;
    const dsrecords = response.answer.filter(r => r.TYPE === RecordType.DS) as ResponseRecord<RecordType.DS>[];
    if (!dsrecords) return [];

    for (const r of dsrecords) {
        const l = r.NAME.join('.');
        const set = SESSIONDSCACHE[l] || [];
        set.push({
            ...r.RDATA,
            expires: (r.TTL * 1000) + now,
        });
        SESSIONDSCACHE[l] = set;
    }

    return SESSIONDSCACHE[label];
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

    const digests: Record<number, Uint32Array> = {};
    for (const d of ds) {  // Find matching DS
        digests[d.digest_type] = digests[d.digest_type] || new Uint32Array(await crypto.subtle.digest(DIGESTS[d.digest_type], data));
        const queryDigest = digests[d.digest_type];
        if (d.key_tag === ksk.RDATA.key_tag &&
            d.algorithm === ksk.RDATA.algorithm) {
            const refDigest = new Uint32Array(d.digest);
            if (refDigest.byteLength === queryDigest.byteLength &&
                refDigest.every((v, i) => v === queryDigest[i])
            ) return true;
        }
    }
    return false;
}

/**
 * Import a DNSKEY record to a CryptoKey for use by crypto library
 * @param rdata DNSKEY record RDATA
 */
export async function importDNSKEY(rdata: RDATA[RecordType.DNSKEY]): Promise<CryptoKey> {
    const algorithm = ALGORITHMS[rdata.algorithm];
    let jwk: JsonWebKey;
    switch (rdata.algorithm) {
        case 8:
            // https://datatracker.ietf.org/doc/html/rfc3110#section-2
            const data = new DataView(rdata.public_key);
            let eLen = data.getUint8(0);
            let offset = 1;
            if (eLen === 0) {
                eLen = data.getUint16(offset);
                offset += 2;
            }
            jwk = {
                kty: "RSA",
                alg: "RS256",  // https://www.rfc-editor.org/rfc/rfc7518#section-3.1
                use: "sig",
                e: base64url_encode(rdata.public_key.slice(offset, offset + eLen)),
                n: base64url_encode(rdata.public_key.slice(offset + eLen)),
                ext: true,
            };
            break;
        case 13:
        case 14:
            // ECDSA public key is only supported via jwk: https://github.com/diafygi/webcrypto-examples/issues/30
            jwk = {
                kty: "EC",
                crv: (algorithm as EcKeyImportParams).namedCurve,
                x: base64url_encode(rdata.public_key.slice(0, rdata.public_key.byteLength/2)),
                y: base64url_encode(rdata.public_key.slice(rdata.public_key.byteLength/2)),
                ext: true,
            };
            break;
        default:
            throw new Error(`Unknown key algorithm ${rdata.algorithm}`);
    }
    return crypto.subtle.importKey("jwk", jwk, algorithm, true, ["verify"]);
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
    if (rrsigs.length === 0) throw new Error('Unable to validate DNSKEY, missing matching RRSIG');

    const now = Math.floor(Date.now() / 1000);

    // Split up rrset on NAME, CLASS, TYPE
    const rrsets = Array.from(response.answer.filter(r => r.TYPE !== RecordType.RRSIG).reduce((acc, rr) => {
        const key = `${rr.NAME}_${rr.CLASS}_${rr.TYPE}`;
        const bin = acc.get(key) || [];
        bin.push(rr);
        acc.set(key, bin);
        return acc;
    }, new Map<string, ResponseRecord<any>[]>()).values());

    match: for (const rrset of rrsets) {
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

        if (rrsigMatches.length === 0) throw new Error(`No matching RRSIG for ${rr}`);
        // The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST match the owner name, algorithm, and key tag for some DNSKEY RR in the zone's apex DNSKEY RRset.
        // The matching DNSKEY RR MUST be present in the zone's apex DNSKEY RRset, and MUST have the Zone Flag bit (DNSKEY RDATA Flag bit 7) set.
        for (const rrsig of rrsigMatches) {
            switch (rr.TYPE) { // TODO check rrset CLASS is valid here
                case RecordType.DNSKEY:
                    const ksk = rrset.find(r => r.RDATA.key_tag === rrsig.RDATA.key_tag && r.RDATA.zone_key);
                    if (ksk === undefined) throw new Error('Unable to validate DNSKEY, missing matching KSK');
                    if (!rr.NAME.join('.').endsWith(rrsig.RDATA.signer.join('.'))) throw new Error('Unable to validate DNSKEY, RRSIG signer mismatch');
                    if (!await validateKSK(ksk, resolver)) throw new Error('Unable to validate DNSKEY, Invalid KSK');
                    // Verify rrset with KSK
                    const key = await importDNSKEY(ksk.RDATA);
                    if (await verifyRRSIG([key], rrsig.RDATA, rrset)) continue match;
                    break;
                case RecordType.DS:
                // The DS record contains a digest of your DNSSEC Key Signing Key (KSK), and acts as a pointer to the next key in the chain of trust.
                // tslint:disable-next-line
                // debugger;
                // break;
                default:
                    // The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST match the owner name, algorithm, and key tag for some DNSKEY RR in the zone's apex DNSKEY RRset.
                    const zsk = await getKeys(rrsig.RDATA.signer, resolver, rrsig.RDATA.key_tag);
                    if (!zsk) throw new Error('Unable to validate RRSIG, no valid ZSK');
                    if (await verifyRRSIG(zsk, rrsig.RDATA, rrset)) continue match;
            }
        }
        return false;
    }
    return true;
}
