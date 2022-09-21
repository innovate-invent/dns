export enum RecordType {
    'A' = 1,    // a host address     [RFC1035]
    'NS' = 2,    // an authoritative name server     [RFC1035]
    'MD' = 3,    // a mail destination (OBSOLETE - use MX)     [RFC1035]
    'MF' = 4,    // a mail forwarder (OBSOLETE - use MX)     [RFC1035]
    'CNAME' = 5,    // the canonical name for an alias     [RFC1035]
    'SOA' = 6,    // marks the start of a zone of authority     [RFC1035]
    'MB' = 7,    // a mailbox domain name (EXPERIMENTAL)     [RFC1035]
    'MG' = 8,    // a mail group member (EXPERIMENTAL)     [RFC1035]
    'MR' = 9,    // a mail rename domain name (EXPERIMENTAL)     [RFC1035]
    'NULL' = 10,    // a null RR (EXPERIMENTAL)     [RFC1035]
    'WKS' = 11,    // a well known service description     [RFC1035]
    'PTR' = 12,    // a domain name pointer     [RFC1035]
    'HINFO' = 13,    // host information     [RFC1035]
    'MINFO' = 14,    // mailbox or mail list information     [RFC1035]
    'MX' = 15,    // mail exchange     [RFC1035]
    'TXT' = 16,    // text strings     [RFC1035]
    'RP' = 17,    // for Responsible Person     [RFC1183]
    'AFSDB' = 18,    // for AFS Data Base location     [RFC1183][RFC5864]
    'X25' = 19,    // for X.25 PSDN address     [RFC1183]
    'ISDN' = 20,    // for ISDN address     [RFC1183]
    'RT' = 21,    // for Route Through     [RFC1183]
    'NSAP' = 22,    // for NSAP address, NSAP style A record     [RFC1706][RFC1348]
    'NSAP-PTR' = 23,    // for domain name pointer, NSAP style     [RFC1348][RFC1637][RFC1706]
    'SIG' = 24,    // for security signature     [RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2931][RFC3110][RFC3008]
    'KEY' = 25,    // for security key     [RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2539][RFC3008][RFC3110]
    'PX' = 26,    // X.400 mail mapping information     [RFC2163]
    'GPOS' = 27,    // Geographical Position     [RFC1712]
    'AAAA' = 28,    // IP6 Address     [RFC3596]
    'LOC' = 29,    // Location Information     [RFC1876]
    'NXT' = 30,    // Next Domain (OBSOLETE)     [RFC3755][RFC2535]
    'EID' = 31,    // Endpoint Identifier     [Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]         1995-06
    'NIMLOC' = 32,    // Nimrod Locator     [1][Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]         1995-06
    'SRV' = 33,    // Server Selection     [1][RFC2782]
    'ATMA' = 34,    // ATM Address     [ ATM Forum Technical Committee, "ATM Name System, V2.0", Doc ID: AF-DANS-0152.000, July 2000. Available from and held in escrow by IANA.]
    'NAPTR' = 35,    // Naming Authority Pointer     [RFC2915][RFC2168][RFC3403]
    'KX' = 36,    // Key Exchanger     [RFC2230]
    'CERT' = 37,    // CERT     [RFC4398]
    'A6' = 38,    // A6 (OBSOLETE - use AAAA)     [RFC3226][RFC2874][RFC6563]
    'DNAME' = 39,    // DNAME     [RFC6672]
    'SINK' = 40,    // SINK     [Donald_E_Eastlake][http://tools.ietf.org/html/draft-eastlake-kitchen-sink]         1997-11
    'OPT' = 41,    // OPT     [RFC6891][RFC3225]
    'APL' = 42,    // APL     [RFC3123]
    'DS' = 43,    // Delegation Signer     [RFC4034][RFC3658]
    'SSHFP' = 44,    // SSH Key Fingerprint     [RFC4255]
    'IPSECKEY' = 45,    // IPSECKEY     [RFC4025]
    'RRSIG' = 46,    // RRSIG     [RFC4034][RFC3755]
    'NSEC' = 47,    // NSEC     [RFC4034][RFC3755]
    'DNSKEY' = 48,    // DNSKEY     [RFC4034][RFC3755]
    'DHCID' = 49,    // DHCID     [RFC4701]
    'NSEC3' = 50,    // NSEC3     [RFC5155]
    'NSEC3PARAM' = 51,    // NSEC3PARAM     [RFC5155]
    'TLSA' = 52,    // TLSA     [RFC6698]
    'SMIMEA' = 53,    // S/MIME cert association     [RFC8162]     SMIMEA/smimea-completed-template     2015-12-01
    // 'Unassigned1' = 54,
    'HIP' = 55,     // Host Identity Protocol     [RFC8005]
    'NINFO' = 56,    // NINFO     [Jim_Reid]     NINFO/ninfo-completed-template     2008-01-21
    'RKEY' = 57,    // RKEY     [Jim_Reid]     RKEY/rkey-completed-template     2008-01-21
    'TALINK' = 58,    // Trust Anchor LINK     [Wouter_Wijngaards]     TALINK/talink-completed-template     2010-02-17
    'CDS' = 59,    // Child DS     [RFC7344]     CDS/cds-completed-template     2011-06-06
    'CDNSKEY' = 60,    // DNSKEY(s) the Child wants reflected in DS     [RFC7344]         2014-06-16
    'OPENPGPKEY' = 61,    // OpenPGP Key     [RFC7929]     OPENPGPKEY/openpgpkey-completed-template     2014-08-12
    'CSYNC' = 62,    // Child-To-Parent Synchronization     [RFC7477]         2015-01-27
    'ZONEMD' = 63,    // message digest for DNS zone     [draft-wessels-dns-zone-digest]     ZONEMD/zonemd-completed-template     2018-12-12
    'SVCB' = 64,       // https://tools.ietf.org/id/draft-nygren-dnsop-svcb-httpssvc-00.html
    'HTTPSSVC' = 65,       // https://tools.ietf.org/id/draft-nygren-dnsop-svcb-httpssvc-00.html
    // 'Unassigned2' = 64-98,
    'SPF' = 99,         // [RFC7208] https://tools.ietf.org/html/rfc4408
    'UINFO' = 100,    // [IANA-Reserved]
    'UID' = 101,    // [IANA-Reserved]
    'GID' = 102,    // [IANA-Reserved]
    'UNSPEC' = 103,    // [IANA-Reserved]
    'NID' = 104,    // [RFC6742]     ILNP/nid-completed-template
    'L32' = 105,    // [RFC6742]     ILNP/l32-completed-template
    'L64' = 106,    // [RFC6742]     ILNP/l64-completed-template
    'LP' = 107,    // [RFC6742]     ILNP/lp-completed-template
    'EUI48' = 108,    // an EUI-48 address     [RFC7043]     EUI48/eui48-completed-template     2013-03-27
    'EUI64' = 109,    // an EUI-64 address     [RFC7043]     EUI64/eui64-completed-template     2013-03-27
    // 'Unassigned3' = 110-248,    // TKEY     249     Transaction Key     [RFC2930]
    'TSIG' = 250,    // Transaction Signature     [RFC2845]
    'IXFR' = 251,    // incremental transfer     [RFC1995]
    'AXFR' = 252,    // transfer of an entire zone     [RFC1035][RFC5936]
    'MAILB' = 253,    // mailbox-related RRs (MB, MG or MR)     [RFC1035]
    'MAILA' = 254,    // mail agent RRs (OBSOLETE - see MX)     [RFC1035]
    '*' = 255,    // A request for some or all records the server has available     [RFC1035][RFC6895][RFC8482]
    'URI' = 256,    // URI     [RFC7553]     URI/uri-completed-template     2011-02-22
    'CAA' = 257,    // Certification Authority Restriction     [RFC8659]     CAA/caa-completed-template     2011-04-07
    'AVC' = 258,    // Application Visibility and Control     [Wolfgang_Riedel]     AVC/avc-completed-template     2016-02-26
    'DOA' = 259,    // Digital Object Architecture     [draft-durand-doa-over-dns]     DOA/doa-completed-template     2017-08-30
    'AMTRELAY' = 260,    // Automatic Multicast Tunneling Relay     [RFC-ietf-mboned-driad-amt-discovery-13]     AMTRELAY/amtrelay-completed-template     2019-02-06
    // 'Unassigned4' = 261-32767,
    'TA' = 32768,   // DNSSEC Trust Authorities     [Sam_Weiler][http://cameo.library.cmu.edu/][ Deploying DNSSEC Without a Signed Root. Technical Report 1999-19, Information Networking Institute, Carnegie Mellon University, April 2004.]         2005-12-13
    'DLV' = 32769,    // DNSSEC Lookaside Validation (OBSOLETE)     [RFC-ietf-dnsop-obsolete-dlv-02][RFC4431]
    // 'Unassigned5' = 32770-65279,    // Private use     65280-65534
    // 'Reserved' = 65535,
}

/*
                                Zone
   Value Algorithm [Mnemonic]  Signing  References   Status
   ----- -------------------- --------- ----------  ---------
     0   reserved
     1   RSA/MD5 [RSAMD5]         n      [RFC2537]  NOT RECOMMENDED
     2   Diffie-Hellman [DH]      n      [RFC2539]   -
     3   DSA/SHA-1 [DSA]          y      [RFC2536]  OPTIONAL
     4   Elliptic Curve [ECC]              TBA       -
     5   RSA/SHA-1 [RSASHA1]      y      [RFC3110]  MANDATORY
   252   Indirect [INDIRECT]      n                  -
   253   Private [PRIVATEDNS]     y      see below  OPTIONAL
   254   Private [PRIVATEOID]     y      see below  OPTIONAL
   255   reserved

   6 - 251  Available for assignment by IETF Standards Action.
 */

// https://en.wikipedia.org/wiki/Domain_Name_System_Security_Extensions#Algorithms
export const ALGORITHMS: Record<number, AlgorithmIdentifier | RsaPssParams | EcdsaParams> = {
    5: { "name": "RSASSA-PKCS1-v1_5", hash: "SHA-1" } as AlgorithmIdentifier | RsaHashedImportParams, // https://datatracker.ietf.org/doc/html/rfc3110
    // 7: { "name": "RSASHA1-NSEC3-SHA1" }, // TODO https://datatracker.ietf.org/doc/html/rfc5155
    8: { "name": "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as AlgorithmIdentifier | RsaHashedImportParams, // https://datatracker.ietf.org/doc/html/rfc5702
    10: { "name": "RSASSA-PKCS1-v1_5", hash: "SHA-512" } as AlgorithmIdentifier | RsaHashedImportParams, // https://datatracker.ietf.org/doc/html/rfc5702
    13: { "name": "ECDSA", hash: "SHA-256", "namedCurve": "P-256" } as EcdsaParams | EcKeyImportParams, // https://datatracker.ietf.org/doc/html/rfc6605
    14: { "name": "ECDSA", hash: "SHA-384", "namedCurve": "P-384" } as EcdsaParams | EcKeyImportParams, // https://datatracker.ietf.org/doc/html/rfc6605
    // 0: { "name": "RSASSA-PKCS1-v1_5" } as Algorithm,
    // 0: { "name": "HMAC" } as Algorithm,
};

// Each DNS query can return one of the following error codes:
export const NODATA = 'NODATA';                // DNS server returned answer with no data.
export const FORMERR = 'FORMERR';                // DNS server claims query was misformatted.
export const SERVFAIL = 'SERVFAIL';            // DNS server returned general failure.
export const NOTFOUND = 'NOTFOUND';            // Domain name not found.
export const NOTIMP = 'NOTIMP';                // DNS server does not implement requested operation.
export const REFUSED = 'REFUSED';            // DNS server refused query.
export const BADQUERY = 'BADQUERY';            // Misformatted DNS query.
export const BADNAME = 'BADNAME';            // Misformatted host name.
export const BADFAMILY = 'BADFAMILY';            // Unsupported address family.
export const BADRESP = 'BADRESP';            // Misformatted DNS reply.
export const CONNREFUSED = 'CONNREFUSED';        // Could not contact DNS servers.
export const TIMEOUT = 'TIMEOUT';            // Timeout while contacting DNS servers.
export const EOF = 'EOF';                // End of file.
export const FILE = 'FILE';                // Error reading file.
export const NOMEM = 'NOMEM';                // Out of memory.
export const DESTRUCTION = 'DESTRUCTION';        // Channel is being destroyed.
export const BADSTR = 'BADSTR';            // Misformatted string.
export const BADFLAGS = 'BADFLAGS';            // Illegal flags specified.
export const NONAME = 'NONAME';            // Given host name is not numeric.
export const BADHINTS = 'BADHINTS';            // Illegal hints flags specified.
export const NOTINITIALIZED = 'NOTINITIALIZED';    // c-ares library initialization not yet performed.
export const LOADIPHLPAPI = 'LOADIPHLPAPI';        // Error loading iphlpapi.dll.
export const ADDRGETNETWORKPARAMS = 'ADDRGETNETWORKPARAMS';// Could not find GetNetworkParams function.
export const CANCELLED = 'CANCELLED';            // DNS query cancelled.

export type ErrorCode =
    'NODATA'
    | 'FORMERR'
    | 'SERVFAIL'
    | 'NOTFOUND'
    | 'NOTIMP'
    | 'REFUSED'
    | 'BADQUERY'
    | 'BADNAME'
    | 'BADFAMILY'
    | 'BADRESP'
    | 'CONNREFUSED'
    | 'TIMEOUT'
    | 'EOF'
    | 'FILE'
    | 'NOMEM'
    | 'DESTRUCTION'
    | 'BADSTR'
    | 'BADFLAGS'
    | 'NONAME'
    | 'BADHINTS'
    | 'NOTINITIALIZED'
    | 'LOADIPHLPAPI'
    | 'ADDRGETNETWORKPARAMS'
    | 'CANCELLED';
