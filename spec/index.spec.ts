import dns from '../src/index.js'
import {DNSError} from "../src/dns.js";

const expect = chai.expect;

const hostname = "example.com";

describe('dns', function() {
    describe('lookup', function () {
        type Options = 4 | 6 | { family: 4 | 6 | 0, hints?: number, all?: boolean, verbatim?: boolean };
        [
            {name: 'no options', options: undefined, address: '93.184.216.34', family: 4},
            {name: '4', options: 4, address: '93.184.216.34', family: 4},
            {name: '{family: 4}', options: {family: 4}, address: '93.184.216.34', family: 4},
            {name: '6', options: 6, address: '2606:2800:220:1:248:1893:25c8:1946', family: 6},
            {name: '{family: 6}', options: {family: 6}, address: '2606:2800:220:1:248:1893:25c8:1946', family: 6},
        ].forEach(function (test) {
            it(`should return ipv${test.family} of ${hostname} given ${test.name}`, function(done){
                function cb(err?: DNSError, address?: string, family?: number) {
                    try {
                        expect(err).to.be.undefined;
                        expect(address).to.equal(test.address);
                        expect(family).to.equal(test.family);
                        done();
                    } catch (e) {
                        done(e);
                    }
                }
                if (test.options) dns.lookup(hostname, test.options as Options, cb);
                else dns.lookup(hostname, cb);
            });
        });
    });

    describe('lookupService', function () {
        it('should throw NOTIMPL', function () {
            expect(()=>dns.lookupService('', 0, (err, hostname1, service) => {})).to.throw(DNSError.NOTIMP);
        });
    });
});
