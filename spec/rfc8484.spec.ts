import Resolver from '../src/rfc8484.js'
import {SOARecord} from "../src/dns.js";

const expect = chai.expect;

import expected from "./expected.js";
import {cmp} from "./common.js";
import {RecordType} from "../src/constants.js";

type Test = {hostname: string, rrval?: (keyof typeof RecordType) | 'ANY', result: any[], cmp?:string[], pending?:boolean};

describe('RFC8484 Resolver', function () {
    it('should cancel requests', function (done) {
        const r = new Resolver();
        r.resolve4(expected.A.host).then(()=>done(new Error("request completed"))).catch(()=>done());
        r.cancel();
    });

    describe('resolve', function(){
        const resolver = new Resolver();
        [
            {hostname: expected.A.host, rrval: undefined, result: expected.A.records},
            {hostname: expected.A.host, rrval: 'ANY', result: [], pending: true},
            ...Object.entries(expected).map(([rrval, v])=>({hostname: v.host, rrval, result: v.records, cmp:v.cmp, pending:v.pending} as Test))
        ].forEach(function (test: Test) {
            it(`should resolve ${test.rrval || 'A'} records for ${test.hostname} given rrval: ${test.rrval}`, test.pending ? undefined : async function () {
                let records = await (test.rrval ? resolver.resolve(test.hostname, test.rrval) : resolver.resolve(test.hostname));
                if (!Array.isArray(records)) records = [records] as any[];
                records.sort();
                if (test.cmp) {
                    cmp(test.result, records, test.cmp);
                } else expect(records).to.eql(test.result);
            });
        });
    });
});
