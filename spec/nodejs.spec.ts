import {promises} from 'dns';

import {SOARecord} from "../src/dns.js";

import {expect} from 'chai';
// @ts-ignore
global.chai = {expect};

import {nodeTypes as expected} from "./expected";
import {cmp} from "./common";
import {RecordType} from "../src/constants";

type Test = {hostname: string, rrval?: (keyof typeof RecordType) | 'ANY', result: any[], cmp?:string[], pending?:boolean, fails?: boolean};

describe('NodeJS DNS Resolver', function () {
    describe('resolve', function(){
        const resolver = new promises.Resolver();
        [
            {hostname: expected.A.host, rrval: undefined, result: expected.A.records},
            {hostname: expected.A.host, rrval: 'ANY', result: [], fails: true},
            ...Object.entries(expected).map(([rrval, v])=>({hostname: v.host, rrval, result: v.records, cmp:v.cmp, pending:false} as Test))
        ].forEach(function (test: Test) {
            it(`should resolve ${test.rrval || 'A'} records for ${test.hostname} given rrval: ${test.rrval}`, test.pending ? undefined : async function () {
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

