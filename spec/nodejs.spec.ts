import {promises} from 'dns';

import {expect} from 'chai';

import {nodeTypes as expected} from "./expected.js";
import {cmp} from "./common.js";
import {RecordType} from "../src/constants.js";

type Test = {hostname: string, rrval?: (keyof typeof RecordType) | 'ANY', result: any[], cmp?:string[], pending?:boolean, fails?: boolean};

/**
 * This suites purpose is to compare the values in expected.ts to what is actually returned by NodeJS.
 * This validates the tests rather than NodeJS.
 * TODO verify error conditions and negative results
 */
describe('NodeJS DNS Resolver', () => {
    describe('resolve', () => {
        const resolver = new promises.Resolver();
        [
            {hostname: expected.A.host, rrval: undefined, result: expected.A.records} as Test,
            {hostname: expected.A.host, rrval: 'ANY', result: [], fails: true} as Test,
            ...Object.entries(expected).map(([rrval, v])=>({hostname: v.host, rrval, result: v.records, cmp:v.cmp, pending:false} as Test))
        ].forEach((test: Test) => {
            it(`should resolve ${test.rrval || 'A'} records for ${test.hostname} given rrval: ${test.rrval}`, test.pending ? undefined : async () => {
                try {
                    let records = await (test.rrval ? resolver.resolve(test.hostname, test.rrval) : resolver.resolve(test.hostname));
                    if (!Array.isArray(records)) records = [records] as any[];
                    records.sort();
                    if (test.cmp) {
                        cmp(test.result, records, test.cmp);
                    } else expect(records).to.eql(test.result);
                } catch (e) {
                    if (!test.fails) throw e;
                }
            });
        });
    });
});

