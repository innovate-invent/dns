import dns from '../src/index.js'
import {DNSError, SOARecord} from "../src/dns.js";
import expected from "./expected.js";
import {cmp} from "./common.js";
import {RecordType} from "../src/constants.js";

const expect = chai.expect;

// tslint:disable:no-unused-expression

function testRRType(f: (host: string, cb: (err?: DNSError, addresses?: any[])=>void)=>void, rrval: keyof typeof RecordType | 'ANY'): void {
    const e = expected[rrval];
    it(`should resolve ${rrval} records from ${e.host}`, done => {
        function cb(err?: DNSError, addresses?: any[]) {
            try {
                if (!Array.isArray(addresses)) addresses = [addresses] as any[];
                addresses.sort();
                expect(err).to.be.undefined;
                cmp(e.records, addresses, e.cmp);
                done();
            } catch (e) {
                done(e);
            }
        }
        f(e.host, cb);
    });
}

describe('dns', () => {
    describe('lookup', () => {
        type Options = 4 | 6 | { family: 4 | 6 | 0, hints?: number, all?: boolean, verbatim?: boolean };
        [
            {name: 'no options', hostname: expected.A.host, options: undefined, address: expected.A.records, family: 4},
            {name: '4', hostname: expected.A.host, options: 4, address: expected.A.records, family: 4},
            {name: '{family: 4}', hostname: expected.A.host, options: {family: 4}, address: expected.A.records, family: 4},
            {name: '6', hostname: expected.AAAA.host, options: 6, address: expected.AAAA.records, family: 6},
            {name: '{family: 6}', hostname: expected.AAAA.host, options: {family: 6}, address: expected.AAAA.records, family: 6},
        ].forEach(test => {
            it(`should return ipv${test.family} of ${test.hostname} given ${test.name}`, done => {
                function cb(err?: DNSError, address?: string, family?: number) {
                    try {
                        expect(err).to.be.undefined;
                        expect(address).to.oneOf(test.address);
                        expect(family).to.equal(test.family);
                        done();
                    } catch (e) {
                        done(e);
                    }
                }
                if (test.options) dns.lookup(test.hostname, test.options as Options, cb);
                else dns.lookup(test.hostname, cb);
            });
        });
    });

    describe('lookupService', () => {
        it('should throw NOTIMP', () => {
            expect(()=>dns.lookupService('', 0, (err, hostname1, service) => undefined)).to.throw(DNSError.NOTIMP);
        });
    });

    describe('getServers', () => {
        it('should return default CloudFlare server', () => {
            expect(dns.getServers()).to.eql(['cloudflare-dns.com']);
        })
    });

    describe('resolve', () => {
        [
            {hostname: expected.A.host, rrval: undefined, result: expected.A.records},
            {hostname: expected.A.host, rrval: 'ANY', result: [], pending: true},
            ...Object.entries(expected).map(([rrval, v]: [string, {host: string, records: any[], cmp?: string[], pending?:boolean}])=>({hostname: v.host, rrval, result: v.records, cmp:v.cmp, pending:v.pending}))
        ].forEach((test: { hostname: string, rrval: string, result: any[], cmp?: string[], pending?: boolean }) => {
            it(`should resolve ${test.rrval || 'A'} records for ${test.hostname} given rrval: ${test.rrval}`, test.pending ? undefined : done => {
                function cb(err?: DNSError, records?: any[] | SOARecord) {
                    try {
                        if (!Array.isArray(records)) records = [records] as any[];
                        records.sort();
                        expect(err).to.be.undefined;
                        if (test.cmp) {
                            cmp(test.result, records, test.cmp);
                        } else expect(records).to.eql(test.result);
                        done();
                    } catch (e) {
                        done(e);
                    }
                }
                const optional: any[] = [];
                if (test.rrval) optional.push(test.rrval);
                dns.resolve(test.hostname, ...optional, cb);
            });
        });
    });

    describe('resolve4', () => {
        [
            {hostname: expected.A.host, result: expected.A.records, options: undefined},
            {hostname: expected.A.host, result: expected.A.records, options: {ttl: true}},
        ].forEach(test => {
            it(`should resolve A records for ${test.hostname} with ttl: ${test.options && test.options.ttl}`, done => {
                function cb(err?: DNSError, addresses?: string[] | {address: string, ttl: boolean}[]) {
                    try {
                        expect(err).to.be.undefined;
                        if (test.options && test.options.ttl) {
                            addresses = (addresses as {address: string, ttl: boolean}[]).map(a=>{expect(a.ttl).to.be.an('number'); return a.address});
                        }
                        expect(addresses).to.eql(test.result);
                        done();
                    } catch (e) {
                        done(e);
                    }
                }
                if (test.options) dns.resolve4(test.hostname, test.options, cb);
                else dns.resolve4(test.hostname, cb);
            });
        });
    });

    describe('resolve6', () => {
        [
            {hostname: expected.AAAA.host, result: expected.AAAA.records, options: undefined},
            {hostname: expected.AAAA.host, result: expected.AAAA.records, options: {ttl: true}},
        ].forEach(test => {
            it(`should resolve AAAA records for ${test.hostname} with ttl: ${test.options && test.options.ttl}`, done => {
                function cb(err?: DNSError, addresses?: string[] | {address: string, ttl: boolean}[]) {
                    try {
                        expect(err).to.be.undefined;
                        expect(addresses).to.not.be.undefined;
                        addresses.sort();
                        if (test.options && test.options.ttl) {
                            addresses = (addresses as {address: string, ttl: boolean}[]).map(a=>{expect(a.ttl).to.be.an('number'); return a.address});
                        }
                        expect(addresses).to.have.members(test.result);
                        done();
                    } catch (e) {
                        done(e);
                    }
                }
                if (test.options) dns.resolve6(test.hostname, test.options, cb);
                else dns.resolve6(test.hostname, cb);
            });
        });
    });

    describe('resolveAny', () => {
        xit('should resolve ANY records', done => {
            // Service doesnt support, can't actually test
        });
    });

    describe('resolveCname', () => {
        testRRType(dns.resolveCname, 'CNAME');
    });

    describe('resolveCaa', () => {
        testRRType(dns.resolveCaa, 'CAA');
    });

    describe('resolveMx', () => {
        testRRType(dns.resolveMx, 'MX');
    });

    describe('resolveNaptr', () => {
        testRRType(dns.resolveNaptr, 'NAPTR');
    });

    describe('resolveNs', () => {
        testRRType(dns.resolveNs, 'NS');
    });

    describe('resolvePtr', () => {
        testRRType(dns.resolvePtr, 'PTR');
    });

    describe('resolveSoa', () => {
        testRRType(dns.resolveSoa, 'SOA');
    });

    describe('resolveSrv', () => {
        testRRType(dns.resolveSrv, 'SRV');
    });

    describe('resolveTxt', () => {
        testRRType(dns.resolveTxt, 'TXT');
    });

    describe('reverse', () => {
        it('should throw NOTIMP', () => {
            expect(()=>dns.reverse('example.com')).to.throw(DNSError.NOTIMP);
        })
    });

    describe('setServers', () => {
        it('should change the server that the default (CloudFlare) resolver makes requests to', () => {
            const old = dns.getServers();
            const updated = ['example.org'];
            dns.setServers(updated);
            expect(dns.getServers()).to.eql(updated);
            dns.setServers(old);
        })
    });
});
