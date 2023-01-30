import {BaseResolver} from "../src/base_resolver.js";
import {DNSError, ResolveOptions} from "../src/dns.js";
import {RecordType} from "../src/constants";

const expect = chai.expect;

class FakeResolver extends BaseResolver {
    public async _fetch(resource: string, options?: RequestInit): Promise<Response> {
        return super._fetch(resource, options);
    }

    resolve(hostname: string, rrtype: (keyof typeof RecordType) | 'ANY', options?: ResolveOptions): Promise<any> {
        throw DNSError.NOTIMP;
    }
}

// https://httpstat.us/
describe('BaseResolver', ()=>{
    describe('_fetch', () => {
        it('should not time out', async () => {
            const resolver = new FakeResolver({timeout: 5000, tries: 1});
            await resolver._fetch("https://httpstat.us/200?sleep=4500");
        }).timeout(6000)
        it('should time out', async () => {
            const resolver = new FakeResolver({timeout: 0, tries: 1});
            try {
                await resolver._fetch("https://httpstat.us/200?sleep=5000");
                expect.fail();
            } catch (e) {
                expect(e).is.eql(DNSError.TIMEOUT);
            }
        })
        it('should abort', async () => {
            const resolver = new FakeResolver({tries: 3, timeout: 500});
            const p = resolver._fetch("https://httpstat.us/200?sleep=5000")
            try {
                resolver.cancel();
                await p;
                expect.fail("did not abort")
            } catch (e) {
                expect(e).to.eql(DNSError.CANCELLED);
            }
        }).timeout(5000)
        it('should validate constructor arguments', () => {
            try {
                const resolver = new FakeResolver({timeout: -2});
                expect.fail("did not validate");
            } catch (e) {
                expect(e).is.instanceof(RangeError);
            }
            try {
                // @ts-ignore
                const resolver = new FakeResolver({timeout: "-1"});
                expect.fail("did not validate");
            } catch (e) {
                expect(e).is.instanceof(TypeError);
            }
            try {
                const resolver = new FakeResolver({tries: 0});
                expect.fail("did not validate");
            } catch (e) {
                expect(e).is.instanceof(RangeError);
            }
            try {
                // @ts-ignore
                const resolver = new FakeResolver({tries: "1"});
                expect.fail("did not validate");
            } catch (e) {
                expect(e).is.instanceof(TypeError);
            }
        })
    })
    describe('reverse', () => {
        it('should throw NOTIMP', () => {
            const resolver = new FakeResolver();
            expect(()=>resolver.reverse("example.com")).to.throw(DNSError.NOTIMP);
        })
    });
})