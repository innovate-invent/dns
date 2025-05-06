import {BaseResolver} from "../src/base_resolver.js";
import {DNSError, ResolveOptions} from "../src/dns.js";
import {RecordType} from "../src/constants.js";
import { expect, assert } from "chai";


class FakeResolver extends BaseResolver {
    protected servers: string[];
    cancel(): void {
        throw new Error("Method not implemented.");
    }
    async resolve(hostname: string | {hostname: string, rrtype: (keyof typeof RecordType)}[], rrtype?: (keyof typeof RecordType) | "ANY" | ResolveOptions, options?: ResolveOptions): Promise<any | any[]> {
        throw DNSError.NOTIMP;
    }
}

// https://httpstat.us/
describe('BaseResolver', () => {
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
    describe('reverse', () => {
        it('should throw NOTIMP', () => {
            const resolver = new FakeResolver();
            expect(() => resolver.reverse("example.com")).to.throw(DNSError.NOTIMP);
        })
    });
})