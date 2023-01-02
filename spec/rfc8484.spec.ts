import Resolver from '../src/rfc8484.js'
import {ResolveOptions} from '../src/dns.js'

const expect = chai.expect;

import expected from "./expected.js";
import {cmp} from "./common.js";
import {RecordType} from "../src/constants.js";
import {Response} from "../src/rfc1035.js";

type Test = {hostname: string, rrval?: (keyof typeof RecordType) | 'ANY', options?:ResolveOptions, result: any[] | Response, cmp?:string[], pending?:boolean};

describe('RFC8484 Resolver', () => {
    it('should cancel requests', done => {
        const r = new Resolver();
        r.resolve4(expected.A.host).then(()=>done(new Error("request completed"))).catch(()=>done());
        r.cancel();
    });

    describe('resolve', () => {
        const resolver = new Resolver();
        [
            {hostname: expected.A.host, rrval: undefined, result: expected.A.records},
            {hostname: expected.A.host, rrval: 'ANY', result: [], pending: true},
            {hostname: expected.A.host, rrval: 'A', result: {
                    "header": {"ID": 0, "QR": 1, "Opcode": 0, "AA": 0, "TC": 0, "RD": 1, "RA": 1, "AD": 0, "CD": 0, "RCODE": 0, "QDCOUNT": 1, "ANCOUNT": 1, "NSCOUNT": 0, "ARCOUNT": 0, "Z": 0},
                    "question": [{"QNAME": ["example", "i2labs", "ca", ""], "QTYPE": 1, "QCLASS": 1}],
                    "answer": [{"NAME": ["example", "i2labs", "ca", ""], "TYPE": 1, "CLASS": 1, "RDLENGTH": 4, "RDATA": [0, 0, 0, 0]}],
                    "authority": [],
                    "additional": []
                }, options: {raw: true}},
            {hostname: expected.A.host, rrval: 'A', result: expected.A.records, options: {dnssec: true}} as Test,
            ...Object.entries(expected).map(([rrval, v])=>({hostname: v.host, rrval, result: v.records, cmp:v.cmp, pending:v.pending, options: v.options} as Test))
        ].forEach((test: Test) => {
            it(`should resolve ${test.rrval || 'A'} records for ${test.hostname} given rrval: ${test.rrval} and options: ${JSON.stringify(test.options)}`, test.pending ? undefined : async () => {
                const args: [any] = [test.hostname];
                if (test.rrval) args.push(test.rrval);
                if (test.options) args.push(test.options);
                let records = await resolver.resolve(...args);
                if (test.options && test.options.raw) {
                    const result = test.result as Response;
                    expect(records.header).to.eql(result.header);
                    expect(records.question).to.eql(result.question);
                    expect(records.authority).to.eql(result.authority);
                    expect(records.additional).to.eql(result.additional);
                    expect(records.answer.length).to.eql(result.answer.length)
                    cmp(result.answer, records.answer, ["NAME", "TYPE", "CLASS", "RDLENGTH", "RDATA"])
                } else {
                    if (!Array.isArray(records)) records = [records] as any[];
                    records.sort();
                    if (test.cmp) {
                        cmp(test.result as any[], records, test.cmp);
                    } else expect(records).to.eql(test.result);
                }
            });
        });
    });
});
