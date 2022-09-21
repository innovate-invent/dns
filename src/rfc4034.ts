import {CLASS, record, Response, ResponseRecord, serialize} from "./rfc1035.js";
import {_rdata, RDATA} from "./rfc_rdata.js"
import {BaseResolver} from "./base_resolver.js";
import {ALGORITHMS, RecordType} from "./constants.js";
import {base64url_decode, base64url_encode} from "./base64url.js";
import {JsonWebKey} from "crypto";
import * as crypto from "crypto";

// RRSIG - Contains a cryptographic signature
// DNSKEY - Contains a public signing key
// DS - Contains the hash of a DNSKEY record, RRSIG for this record is signed by parent
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
    keys: CryptoKey[]
}

type StoredCryptoKeys = Expires & Signed & {
    keys: JsonWebKey[]
}

type SigningKey = CryptoKey & Expires;

// The following should be protected by the JS engine from any external code trying to inject values
let ROOTDIGESTS: CachedDS = [];
let SESSIONDSCACHE: Record<string, CachedDS> = {};
let SESSIONKEYCACHE: Record<string, CachedCryptoKeys> = {};

const STOREKEYPREFIX = "@i2labs.ca/dns/keys/"  // localStore key prefix for DNS Zone Keys
const STOREDSPREFIX = "@i2labs.ca/dns/ds/";  // localStore key prefix for DS records

/**
 * Helper to deserialize CryptoKeys from localStore cache
 * @param owner name of DNSKEY owner in canonical form (lowercase)
 */
async function getKeys(owner: string[]): Promise<CryptoKey[]> {
    const now = Date.now();
    const label = `${STOREKEYPREFIX}${owner.join('.')}`;
    if (label in SESSIONKEYCACHE) {
        const keys = SESSIONKEYCACHE[label];
        if (now >= keys.expires) {
            delete SESSIONKEYCACHE[label];
            return [];
        }
        return keys.keys;
    }
    const s = localStorage.getItem(label);
    if (s) {
        let keys: StoredCryptoKeys = JSON.parse(s);
        if (now >= keys.expires) {
            localStorage.removeItem(label);
            return [];
        }
        // Validate keys from storage
        // TODO
        return Promise.all(keys.keys.map(async jwk=>{
            const key = crypto.subtle.importKey("jwk", jwk, jwk.alg as string, true, jwk.key_ops as KeyUsage[]);
            return key;
        }));
    }
    return [];
}

async function setKeys(owner: string[], keys: CryptoKey[], expires: number, rrsig_rdata: RDATA[RecordType.RRSIG]) {
    const label = `${STOREKEYPREFIX}${owner.join('.')}`;
    if (Date.now() >= expires) return;
    SESSIONKEYCACHE[label] = {keys, expires};
    localStorage.setItem(label, JSON.stringify({
        owner,
        keys: (await Promise.all(keys.map(async key=>({alg: key.algorithm, ... await crypto.subtle.exportKey("jwk", key)})))),
        expires,
        rrsig: {
            original_ttl: rrsig_rdata.original_ttl,
            sig_expiration: rrsig_rdata.sig_expiration,
            sig_inception: rrsig_rdata.sig_inception,
            signer: rrsig_rdata.signer,
            signature: base64url_encode(rrsig_rdata.signature),
        }
    }));
}

/**
 * Helper to retrieve IANA root anchor digests for validating DS chain
 */
async function getRootDS(): Promise<typeof ROOTDIGESTS> {
    const now = Date.now();
    ROOTDIGESTS = ROOTDIGESTS.filter(d=>d.expires > now);
    if (!ROOTDIGESTS) {
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
    }
    return ROOTDIGESTS;
}

async function validateDS(key: SigningKey, ds: StoredDS) {
    // Reconstruct rrsig and ds rrset
    const rrsig_data: RDATA[RecordType.RRSIG] = {
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
    return verifyRRSIG(key, rrsig_data, rrset);
}

/**
 * Validate a provided Key Signing Key by looking up the respective DS record and comparing the digest
 * DS records are cached in localStorage, and revalidated when read from storage to protect from injection attacks
 * @param ksk KSK record to validate
 * @param resolver An instance of a resolver used to make requests for the DS records
 */
export async function validateKSK(ksk: ResponseRecord<RecordType.DNSKEY>, resolver: BaseResolver): Promise<boolean> {
    if (!ksk.RDATA.zone_key) return false;  // The DNSKEY RR referred to in the DS RR MUST be a DNSSEC zone key.
    let ds: CachedDS;
    if (ksk.NAME.length === 1) ds = await getRootDS();  // Root key
    else {
        const now = Date.now();
        const label = `${STOREDSPREFIX}${ksk.NAME.join('.')}`;
        if (label in SESSIONDSCACHE) {
            ds = SESSIONDSCACHE[label].filter(d=>d.expires > now);
            SESSIONDSCACHE[label] = ds;
        }
        if (!ds) {
            const s = localStorage.getItem(label);
            let stored_ds: StoredDS;
            if (s) {
                stored_ds = JSON.parse(s) as StoredDS;
                stored_ds.ds.forEach((d: RDATA[RecordType.DS]) => d.digest = base64url_decode(d.digest as unknown as string));
                stored_ds.rrsig.signature = base64url_decode(stored_ds.rrsig.signature as unknown as string);
            }
            if (!stored_ds) {
                // Fetch DS
                const response = await resolver.resolve(ksk.NAME.join('.'), "DS", {
                    raw: true,
                    dnssec: true
                }) as Response;
                const ds_response = response.answer.filter(r => r.TYPE === RecordType.DS) as ResponseRecord<RecordType.DS>[];
                const rrsig = response.answer.find(r => r.TYPE === RecordType.RRSIG && (r as ResponseRecord<RecordType.RRSIG>).RDATA.type_covered === RecordType.DS) as ResponseRecord<RecordType.RRSIG>;
                if (ds_response) {
                    const dsset: Record<string, StoredDS> = {};
                    for (const r of ds_response) {
                        const l = `${STOREDSPREFIX}${r.NAME.join('.')}`;
                        const set = dsset[l] || [];
                        set.push({
                            ...r.RDATA,
                            expires: (r.TTL * 1000) + now,
                            rrsig: {
                                original_ttl: rrsig.RDATA.original_ttl,
                                sig_expiration: rrsig.RDATA.sig_expiration,
                                sig_inception: rrsig.RDATA.sig_inception,
                                signer: rrsig.RDATA.signer,
                                signature: rrsig.RDATA.signature
                            }
                        });
                        dsset[l] = set;
                    }
                    ds = dsset[label].ds;
                    Object.entries(dsset).forEach(([k, v]: [string, CachedDS[]]) => localStorage.setItem(k, JSON.stringify(v.map(d => ({
                        ...d,
                        digest: base64url_encode(d.digest),
                        rrsig: {...d.rrsig, signature: base64url_encode(d.rrsig.signature)}
                    })))));
                }
            }
            if (stored_ds) {
                if (!validateDS(k, stored_ds)) throw new Error('Invalid DS record for ' + ksk.NAME);
                ds = stored_ds.ds;
            }
        }
        if (!ds) ds = await getRootDS();  // Just shove in root DS if nothing found
    }
    for (const d of ds) {
        if (d.key_tag === ksk.RDATA.key_tag && d.algorithm === ksk.RDATA.algorithm) {
            // digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
            // DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.  "|" denotes concatenation
            const data = new ArrayBuffer(ksk.RDLENGTH + ksk.NAME.length + ksk.NAME.reduce((acc, cur)=>acc + cur.length, 0));
            const encoder = serialize(data);
            encoder.next();
            encoder.next(['string[]', ksk.NAME.map(v=>v.toLowerCase())]);
            encoder.next(['opaque', new Uint8Array(ksk.raw_rdata)]);
            if (d.digest === await crypto.subtle.digest(ALGORITHMS[d.digest_type], data)) return true;
        }
    }
    return false;
}

export async function importDNSKEY(key: ResponseRecord<RecordType.DNSKEY>): Promise<CryptoKey> {
    const algorithm = ALGORITHMS[key.RDATA.algorithm];
    switch (key.RDATA.algorithm) {
        case 13:
        case 14:
            // EDCSA public key is only supported via jwk: https://github.com/diafygi/webcrypto-examples/issues/30
            const jwk: JsonWebKey = {
                kty: "EC",
                crv: (algorithm as EcKeyImportParams).namedCurve,
                x: base64url_encode(key.RDATA.public_key.slice(0, key.RDATA.public_key.byteLength/2)),
                y: base64url_encode(key.RDATA.public_key.slice(key.RDATA.public_key.byteLength/2)),
                ext: true,
            };
            return crypto.subtle.importKey("jwk", jwk, algorithm, true, ["verify"]);
        default:
            return crypto.subtle.importKey("raw", key.RDATA.public_key, algorithm, true, ["verify"]);
    }
}

export function labelCount(name: string[]): number {
    let ownerNameLen = name.length;
    // Root (".") has a Labels field value of 0 and
    // The value of the Labels field MUST NOT count either the wildcard label (if present)
    if (name[0] === '*' || name[0] === '') ownerNameLen--;
    // or the null (root) label that terminates the owner name
    if (name[name.length - 1] === '') ownerNameLen--;
    return ownerNameLen;
}

export async function verifyRRSIG(key: CryptoKey, rrsig_data: RDATA[RecordType.RRSIG], rrset: ResponseRecord<any>[]): Promise<boolean> {
    if (rrsig_data.type_covered === RecordType.DNSKEY) {
        // Check for KSK and use that
        // TODO
    }
    // Else check for zsk and use that
    if (!(rrsig_data.algorithm in ALGORITHMS)) throw new Error("Unable to verify rrsig, unsupported algorithm " + rrsig_data.algorithm);
    return crypto.subtle.verify(ALGORITHMS[rrsig_data.algorithm], key, rrsig_data.signature, signedData(rrsig_data, rrset));
}

export function signedData(rrsig_data: RDATA[RecordType.RRSIG], rrset: ResponseRecord<any>[]): ArrayBuffer {
    // signed_data = RRSIG_RDATA | RR(1) | RR(2)...
    let bufferLen = 18 + rrsig_data.signer.reduce((acc, cur) => acc + cur.length, 0) + rrsig_data.signer.length;
    for (const rr of rrset) {
        bufferLen += rr.NAME.reduce((acc, cur) => acc + cur.length, 0) + rr.NAME.length;
        bufferLen += 10; // type | class | OrigTTL | RDATA length
        bufferLen += rr.RDLENGTH;
    }
    const signedData = new ArrayBuffer(bufferLen);
    const encoder = serialize(signedData);
    encoder.next();

    // RRSIG_RDATA is the wire format of the RRSIG RDATA fields with the Signature field excluded and the Signer's Name in canonical form.
    for (const [field, type] of Object.entries(_rdata.get(RecordType.RRSIG))) {
        if (field === "signer") {
            encoder.next([type, rrsig_data.signer.map(v => v.toLowerCase())]);
        } else if (field !== "signature") {
            encoder.next([type, rrsig_data[field as keyof RDATA[RecordType.RRSIG]]]);
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
                    if (rrsig_data.labels < val.length-1) val = ["*", ...val.slice(-(rrsig_data.labels+1))];
                    val = (val as string[]).map(v => v.toLowerCase());
                    break;
                case "TTL":
                    // the RR's TTL is set to its original value as it appears in the originating authoritative zone or the Original TTL field of the covering RRSIG RR.
                    val = rrsig_data.original_ttl;
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
    return signedData;
}

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
            r.RDATA.signer.join(".") === rr.NAME.join(".") &&  // The RRSIG RR's Signer's Name field MUST be the name of the zone that contains the RRset.
            r.RDATA.labels <= labelCount(rr.NAME) &&  // The number of labels in the RRset owner name MUST be greater than or equal to the value in the RRSIG RR's Labels field.
            r.RDATA.sig_expiration >= now &&  // The validator's notion of the current time MUST be less than or equal to the time listed in the RRSIG RR's Expiration field.
            r.RDATA.sig_inception <= now  // The validator's notion of the current time MUST be greater than or equal to the time listed in the RRSIG RR's Inception field.
        );
        // The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST match the owner name, algorithm, and key tag for some DNSKEY RR in the zone's apex DNSKEY RRset.
        // The matching DNSKEY RR MUST be present in the zone's apex DNSKEY RRset, and MUST have the Zone Flag bit (DNSKEY RDATA Flag bit 7) set.
        for (const rrsig of rrsigMatches) {
            switch (rr.TYPE) { // TODO check rrset CLASS is valid here
                case RecordType.DNSKEY:
                    if (rr.NAME.length === 1) {  // Root DNSKEY


                    }
                    const ksk = rrset.find(r => r.RDATA.key_tag === rrsig.RDATA.key_tag && r.RDATA.zone_key);
                    if (ksk === undefined) throw new Error('Unable to validate DNSKEY, missing matching KSK');
                    if (rrsig.RDATA.signer.join('.') !== rr.NAME.join('.')) throw new Error('Unable to validate DNSKEY, RRSIG signer mismatch');
                    // Verify rrset with KSK
                    const key = await importDNSKEY(ksk);
                    if (!await verifyRRSIG(key, rrsig.RDATA, rrset)) throw new Error('Invalid KSK');
                    // Fetch DS chain for KSK
                    const ds = await resolver.resolve(rrsig.RDATA.signer.join('.'), 'DS', {raw: true, dnssec: true});
                    // Verify ZSK with KSK
                    // if (!(zsk.RDATA.algorithm in ALGORITHMS)) throw new Error('Unsupported encryption algorithm');
                    // if (!await crypto.subtle.verify(ALGORITHMS[zsk.RDATA.algorithm], ksk, rrsig.RDATA.signature, zsk.RDATA.public_key)) throw new Error('Invalid ZSK');
                    // Verify DNSKEY with ZSK (KSK signs itself)
                    break;
                case RecordType.DS:
                    // The DS record contains a digest of your DNSSEC Key Signing Key (KSK), and acts as a pointer to the next key in the chain of trust.
                    // tslint:disable-next-line
                    //debugger;
                    //break;
                default:
                    // The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST match the owner name, algorithm, and key tag for some DNSKEY RR in the zone's apex DNSKEY RRset.
                    let zsk = SIGNINGKEYS.get(`${rrsig.RDATA.key_tag}_${rrsig.NAME.join('.')}`);
                    if (!zsk || zsk.expires <= now) {
                        // The matching DNSKEY RR MUST be present in the zone's apex DNSKEY RRset, and MUST have the Zone Flag bit (DNSKEY RDATA Flag bit 7) set.
                        const rrzsk = (await resolver.resolve(rrsig.RDATA.signer.join('.'), 'DNSKEY', {
                            raw: true,
                            dnssec: true
                        }) as Response)
                            .answer.filter(r => r.TYPE === RecordType.DNSKEY && (r as ResponseRecord<RecordType.DNSKEY>).RDATA.zone_key) as ResponseRecord<RecordType.DNSKEY>[];
                        for (const r of rrzsk) {
                            if (!(r.RDATA.algorithm in ALGORITHMS)) throw new Error("Unable to import zone signing key, unsupported algorithm " + r.RDATA.algorithm);

                            SIGNINGKEYS.set(`${r.RDATA.key_tag}_${r.NAME.join('.')}`,
                            );
                        }
                        zsk = SIGNINGKEYS.get(`${rrsig.RDATA.key_tag}_${rrsig.NAME.join('.')}`);
                    }
                    if (!zsk || zsk.expires <= now) throw new Error('Unable to validate RRSIG, no valid ZSK');
                    return await verifyRRSIG(zsk, rrsig.RDATA, rrset);
            }
        }
        return false;
    }))).every(x => x)
}
