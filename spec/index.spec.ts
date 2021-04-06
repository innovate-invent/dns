import dns from '../src/index.js'
import {DNSError, SOARecord} from "../src/dns.js";

const expect = chai.expect;

import expected from "./expected.js";
import {cmp} from "./common.js";
import {RecordType} from "../src/constants";


function test(f: (host: string, cb: (err?: DNSError, addresses?: any[])=>void)=>void, rrval: keyof typeof RecordType | 'ANY'): void {
    const e = expected[rrval];
    it(`should resolve ${rrval} records from ${e.host}`, function (done) {
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

describe('dns', function() {
    describe('lookup', function () {
        type Options = 4 | 6 | { family: 4 | 6 | 0, hints?: number, all?: boolean, verbatim?: boolean };
        [
            {name: 'no options', hostname: expected.A.host, options: undefined, address: expected.A.records, family: 4},
            {name: '4', hostname: expected.A.host, options: 4, address: expected.A.records, family: 4},
            {name: '{family: 4}', hostname: expected.A.host, options: {family: 4}, address: expected.A.records, family: 4},
            {name: '6', hostname: expected.AAAA.host, options: 6, address: expected.AAAA.records, family: 6},
            {name: '{family: 6}', hostname: expected.AAAA.host, options: {family: 6}, address: expected.AAAA.records, family: 6},
        ].forEach(function (test) {
            it(`should return ipv${test.family} of ${test.hostname} given ${test.name}`, function(done){
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

    describe('lookupService', function () {
        it('should throw NOTIMP', function () {
            expect(()=>dns.lookupService('', 0, (err, hostname1, service) => {})).to.throw(DNSError.NOTIMP);
        });
    });

    describe('getServers', function(){
        it('should return default CloudFlare server', function () {
            expect(dns.getServers()).to.eql(['cloudflare-dns.com']);
        })
    });

    describe('resolve', function(){
        [
            {hostname: expected.A.host, rrval: undefined, result: expected.A.records},
            {hostname: expected.A.host, rrval: 'ANY', result: [], pending: true},
            ...Object.entries(expected).map(([rrval, v]: [string, {host: string, records: any[], cmp?: string[], pending?:boolean}])=>({hostname: v.host, rrval, result: v.records, cmp:v.cmp, pending:v.pending}))
        ].forEach(function (test: {hostname: string, rrval: string, result: any[], cmp?:string[], pending?:boolean}) {
            it(`should resolve ${test.rrval || 'A'} records for ${test.hostname} given rrval: ${test.rrval}`, test.pending ? undefined : function (done) {
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
                if (test.rrval) dns.resolve(test.hostname, test.rrval, cb);
                else dns.resolve(test.hostname, cb);
            });
        });
    });

    describe('resolve4', function(){
        [
            {hostname: expected.A.host, result: expected.A.records, options: undefined},
            {hostname: expected.A.host, result: expected.A.records, options: {ttl: true}},
        ].forEach(function (test) {
            it(`should resolve A records for ${test.hostname} with ttl: ${test.options && test.options.ttl}`, function(done){
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

    describe('resolve6', function(){
        [
            {hostname: expected.AAAA.host, result: expected.AAAA.records, options: undefined},
            {hostname: expected.AAAA.host, result: expected.AAAA.records, options: {ttl: true}},
        ].forEach(function (test) {
            it(`should resolve AAAA records for ${test.hostname} with ttl: ${test.options && test.options.ttl}`, function(done){
                function cb(err?: DNSError, addresses?: string[] | {address: string, ttl: boolean}[]) {
                    try {
                        addresses.sort();
                        expect(err).to.be.undefined;
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

    describe('resolveAny', function(){
        xit('should resolve ANY records', function (done) {
            // Service doesnt support, can't actually test
        });
    });

    describe('resolveCname', function(){
        test(dns.resolveCname, 'CNAME');
    });

    describe('resolveCaa', function(){
        test(dns.resolveCaa, 'CAA');
    });

    describe('resolveMx', function(){
        test(dns.resolveMx, 'MX');
    });

    describe('resolveNaptr', function(){
        test(dns.resolveNaptr, 'NAPTR');
    });

    describe('resolveNs', function(){
        test(dns.resolveNs, 'NS');
    });

    describe('resolvePtr', function(){
        test(dns.resolvePtr, 'PTR');
    });

    describe('resolveSoa', function(){
        test(dns.resolveSoa, 'SOA');
    });

    describe('resolveSrv', function(){
        test(dns.resolveSrv, 'SRV');
    });

    describe('resolveTxt', function(){
        test(dns.resolveTxt, 'TXT');
    });

    describe('reverse', function(){
        it('should throw NOTIMP', function () {
            expect(()=>dns.reverse()).to.throw(DNSError.NOTIMP);
        })
    });

    describe('setServers', function(){
        it('should change the server that the default (CloudFlare) resolver makes requests to', function () {
            const old = dns.getServers();
            dns.setServers(['example.org']);
            expect(dns.getServers()).to.eql(dns.getServers());
            dns.setServers(old);
        })
    });
});
