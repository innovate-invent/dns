// Hijack fetch to inject IANA response into getRootDS
import {restoreFetch, setFetch} from "./common.js";

import {
    canonicalSortLabels,
    importDNSKEY,
    labelCount,
    signedData,
    validateKSK,
    validateRecords,
    verifyRRSIG,
    clearCaches, isSameOrSubDomain,
} from '../src/rfc4034.js'
import {ALGORITHMS, DIGESTS, RecordType} from "../src/constants.js";
import {RDATA} from "../src/rfc_rdata.js";
import {AnswerRecord, CLASS, DNSResponse, Question, ResponseRecord} from "../src/rfc1035.js";
import {BaseResolver} from "../src/base_resolver.js";
import {ResolveOptions} from '../src/dns.js';
import { expect, assert, use as chaiUse } from "chai";
import chaiAsPromised from 'chai-as-promised';
chaiUse(chaiAsPromised);

// eslint-disable:no-unused-expression

describe('RFC4034 DNSSEC', () => {
    describe('label count', () => {
        it('should handle a basic case of example.i2labs.ca', () => expect(labelCount(['example', 'i2labs', 'ca', ''])).to.eql(3))
        it('should not count wildcards', () => expect(labelCount(['*', 'example', 'i2labs', 'ca', ''])).to.eql(3))
        it('should not count the root', () => expect(labelCount([''])).to.eql(0))
        it('should handle a TLD', () => expect(labelCount(['ca', ''])).to.eql(1))
    })

    describe('determine if domain is subdomain or equal', () => {
        it('should handle the domains being equal', () => {
            expect(isSameOrSubDomain(['example', 'com', ''], ['example', 'com', ''])).to.be.true;
        })
        it('should handle the domain being a subdomain', () => {
            expect(isSameOrSubDomain(['sub', 'example', 'com', ''], ['example', 'com', ''])).to.be.true;
            expect(isSameOrSubDomain(['dub', 'sub', 'example', 'com', ''], ['example', 'com', ''])).to.be.true;
        })
        it('should handle the zone being a subdomain', () => {
            expect(isSameOrSubDomain(['example', 'com', ''], ['sub', 'example', 'com', ''])).to.be.false;
            expect(isSameOrSubDomain(['example', 'com', ''], ['dub', 'sub', 'example', 'com', ''])).to.be.false;
        })
        it('should reject the domains being different', () => {
            expect(isSameOrSubDomain(['example', 'com', ''], ['example', 'ca', ''])).to.be.false;
            expect(isSameOrSubDomain(['example', 'ca', ''], ['example', 'com', ''])).to.be.false;
        })
        it('should reject the zone being a substring of the lowest level domain', () => {
            expect(isSameOrSubDomain(['aexample', 'com', ''], ['example', 'com', ''])).to.be.false;
        })
        it('should not modify the arguments', ()=>{
            const op1 = ['example', 'com', ''];
            const op2 = ['example', 'com', ''];
            expect(isSameOrSubDomain(op1, op2)).to.be.true;
            expect(op1, 'argument 1 modified').to.deep.eq(['example', 'com', '']);
            expect(op2, 'argument 2 modified').to.deep.eq(['example', 'com', '']);
        })
    })

    describe('canonical sorting of labels', () => {
        it('should handle a basic case of example1.i2labs.ca and example2.i2labs.ca', () => expect(canonicalSortLabels([['example1', 'i2labs', 'ca', ''], ['example2', 'i2labs', 'ca', '']])).to.eql([['example1', 'i2labs', 'ca', ''], ['example2', 'i2labs', 'ca', '']]))
        it('should handle a basic case of example1.i2labs.ca and example2.i2labs.ca', () => expect(canonicalSortLabels([['example1', 'i2labs', 'ca', ''], ['example2', 'i2labs', 'ca', '']])).to.eql([['example1', 'i2labs', 'ca', ''], ['example2', 'i2labs', 'ca', '']]))
        it('should be case insensitive, forcing everything to lowercase', () => expect(canonicalSortLabels([['example2', 'i2labs', 'ca', ''], ['EXAMPLE1', 'I2LABS', 'CA', '']])).to.eql([['example1', 'i2labs', 'ca', ''], ['example2', 'i2labs', 'ca', '']]))
        it('should handle the example provided in the spec', () => expect(canonicalSortLabels([
            ['\x80', 'z', 'example'],
            ['*', 'z', 'example'],
            ['\x01', 'z', 'example'],
            ['z', 'example'],
            ['zABC', 'a', 'EXAMPLE'],
            ['Z', 'a', 'example'],
            ['yljkjljk', 'a', 'example'],
            ['a', 'example'],
            ['example'],
        ])).to.eql([
            ['example'],
            ['a', 'example'],
            ['yljkjljk', 'a', 'example'],
            ['z', 'a', 'example'],
            ['zabc', 'a', 'example'],
            ['z', 'example'],
            ['\x01', 'z', 'example'],
            ['*', 'z', 'example'],
            ['\x80', 'z', 'example'],
        ]))
    })

    describe('DNSKEY import', () => {
        it('should error for unknown algorithms', () => {
            return expect(importDNSKEY({
                zone_key: true,
                secure_entry_point: false,
                protocol: 255,
                algorithm: 0,
                public_key: new ArrayBuffer(0),
                key_tag: 0
            } as RDATA[RecordType.DNSKEY])).to.eventually.be.rejectedWith('not implemented')
        })
        it('should handle RSASSA-PKCS1-v1_5 SHA-1', async () => {
            // Generate test data via
            // openssl genrsa -out key.pem 4096
            // openssl pkey -pubout < key.pem | tail -n+2 | head -n-1 | tr -d '\n' | xclip and paste into the
            // public key
            // openssl dgst -sign key.pem -keyform PEM -sha1 -binary <<<"helloworld" | base64 -w0 | xclip and paste
            // into the sig string
            const key = await importDNSKEY({
                zone_key: true,
                secure_entry_point: false,
                protocol: 3,
                algorithm: 5,
                public_key: Uint8Array.from(atob('AwEAAZ2ffBGbn8kvd4y7RzDFFOLYT6RwHsOt3O2SPjXns+59DFvXAQC8nMYxHtMbGgDNo80BGb/E03R5tsZjqfzLw6cgMZnf6Z9OUK1Iz8eC785Bl2+WNsVsGUAAOnwIIqjilE69MbxoLr0yAycpVWeQdVkhajCCibPNB7znkxZLczO1lLd345DRyNnWzOArFn/LzEDHsSB/dnVP8pj9gG+t84l8Bu7GWxE9Ld2JI+RJHHemd+E7DGO4/ec4vU2V2KQ4N5k5xGI7ehZW0qb+6/TxCKAFzDFMbKW4Y4mTxb/UXbHqEM+c8qX+D0vfH11/3NnR8Mn7JDnBMKdz7+Jf0Wiv0UU='), c => c.charCodeAt(0)).buffer,
                key_tag: 0
            } as RDATA[RecordType.DNSKEY]);
            expect(key.algorithm.name).to.eq('RSASSA-PKCS1-v1_5');
            expect(key.type).to.eq('public');
            expect(key.usages).to.include('verify');
            return expect(crypto.subtle.verify(ALGORITHMS[5], key, Uint8Array.from(atob('VfKcn15agCUifHL6pne6b4dajLAjzI99oml/Ddr2v/VFhIHY8e8Nq6+4i84EIvjd9GhyR7cnqgPE8RErLvNDzHDdL92yzyBZzojEfuYru1P5mHxN+unYqwY9s52dAQi2JItcdosN3p6By3jbEt2eYnWpa4D4EDmIpKqaFEf7sMEY5Z0jbDtByPcyWTWoqhYRih0h6HRh1ootKgDhDAt0PHP/JJxO2wdfFUM34alb8+uXNi0Mk53MMdCgpZBrYbPYGH9oxAQeXiZxrTvjv2RkE4Br3rUoUwpmEw3bgEXOCBS7jGSvnGtlewYEvchWs+I/kmVa6GDpduyGdVlT/Uar9w=='), c => c.charCodeAt(0)), Uint8Array.from("helloworld", c => c.charCodeAt(0)))).to.eventually.be.true;
        })
        it('should handle RSASSA-PKCS1-v1_5 SHA-1 NSEC3', async () => {
            // Generate test data via `dnssec-keygen -a NSEC3RSASHA1 -b 4096 -n ZONE example.com` and paste in hash
            // with spaces removed
            const key = await importDNSKEY({
                zone_key: true,
                secure_entry_point: false,
                protocol: 3,
                algorithm: 7,
                public_key: Uint8Array.from(atob('AwEAAZ1WZwDQiXUiJ0CUdJSttME3nMVWTRzU22iyyXP/s11IMNqKEMo9yoQ/8Rq3zLcRDLoyfhuWoX5XlBAqKoOO/QXGiNPQvvE6DxmkbN9WCtcz+fewHgHQhl922PdVnbzauNGX7aXLnISwjUFYuystb/AMEfvkfudrw12x0FC/oJMrxL6f53HgsvDCSpzjIF2wrtB54+HW8+RirYhPBGaxwjT7H/HzPPtvMXzmvyvXeS5kt6iANVLSOVrWNDoGZ6ZnVnTsfs9pLeEdsBwUkFgggccKnXE2L07/JbTgDaXlmAfzG2rVfbVlrYOO36R8lUN6u+0GK+yKvWS2u2d08bu6/GE='), c => c.charCodeAt(0)).buffer,
                key_tag: 0
            } as RDATA[RecordType.DNSKEY]);
            expect(key.algorithm.name).to.eq('RSASSA-PKCS1-v1_5');
            expect(key.type).to.eq('public');
            expect(key.usages).to.include('verify');
            // Sig validation not needed as it is identical to non-NSEC3
        })
        it('should handle RSASSA-PKCS1-v1_5 SHA-256', async () => {
            // openssl genrsa -out key.pem 4096
            // openssl pkey -pubout < key.pem | tail -n+2 | head -n-1 | tr -d '\n' | xclip and paste into the
            // public key
            // openssl dgst -sign key.pem -keyform PEM -sha256 -binary <<<"helloworld" | base64 -w0 | xclip and paste
            // into the sig string
            const key = await importDNSKEY({
                zone_key: true,
                secure_entry_point: false,
                protocol: 3,
                algorithm: 8,
                public_key: Uint8Array.from(atob('AwEAAZ2ffBGbn8kvd4y7RzDFFOLYT6RwHsOt3O2SPjXns+59DFvXAQC8nMYxHtMbGgDNo80BGb/E03R5tsZjqfzLw6cgMZnf6Z9OUK1Iz8eC785Bl2+WNsVsGUAAOnwIIqjilE69MbxoLr0yAycpVWeQdVkhajCCibPNB7znkxZLczO1lLd345DRyNnWzOArFn/LzEDHsSB/dnVP8pj9gG+t84l8Bu7GWxE9Ld2JI+RJHHemd+E7DGO4/ec4vU2V2KQ4N5k5xGI7ehZW0qb+6/TxCKAFzDFMbKW4Y4mTxb/UXbHqEM+c8qX+D0vfH11/3NnR8Mn7JDnBMKdz7+Jf0Wiv0UU='), c => c.charCodeAt(0)).buffer,
                key_tag: 0
            } as RDATA[RecordType.DNSKEY]);
            expect(key.algorithm.name).to.eq('RSASSA-PKCS1-v1_5');
            expect(key.type).to.eq('public');
            expect(key.usages).to.include('verify');
            return expect(crypto.subtle.verify(ALGORITHMS[8], key, Uint8Array.from(atob('VfKcn15agCUifHL6pne6b4dajLAjzI99oml/Ddr2v/VFhIHY8e8Nq6+4i84EIvjd9GhyR7cnqgPE8RErLvNDzHDdL92yzyBZzojEfuYru1P5mHxN+unYqwY9s52dAQi2JItcdosN3p6By3jbEt2eYnWpa4D4EDmIpKqaFEf7sMEY5Z0jbDtByPcyWTWoqhYRih0h6HRh1ootKgDhDAt0PHP/JJxO2wdfFUM34alb8+uXNi0Mk53MMdCgpZBrYbPYGH9oxAQeXiZxrTvjv2RkE4Br3rUoUwpmEw3bgEXOCBS7jGSvnGtlewYEvchWs+I/kmVa6GDpduyGdVlT/Uar9w=='), c => c.charCodeAt(0)), Uint8Array.from("helloworld", c => c.charCodeAt(0)))).to.eventually.be.true;
        })
        it('should handle RSASSA-PKCS1-v1_5 SHA-512', async () => {
            // openssl genrsa -out key.pem 4096
            // openssl pkey -pubout < key.pem | tail -n+2 | head -n-1 | tr -d '\n' | xclip and paste into the
            // public key
            // openssl dgst -sign key.pem -keyform PEM -sha512 -binary <<<"helloworld" | base64 -w0 | xclip and paste
            // into the sig string
            const key = await importDNSKEY({
                zone_key: true,
                secure_entry_point: false,
                protocol: 3,
                algorithm: 10,
                public_key: Uint8Array.from(atob('AwEAAZ2ffBGbn8kvd4y7RzDFFOLYT6RwHsOt3O2SPjXns+59DFvXAQC8nMYxHtMbGgDNo80BGb/E03R5tsZjqfzLw6cgMZnf6Z9OUK1Iz8eC785Bl2+WNsVsGUAAOnwIIqjilE69MbxoLr0yAycpVWeQdVkhajCCibPNB7znkxZLczO1lLd345DRyNnWzOArFn/LzEDHsSB/dnVP8pj9gG+t84l8Bu7GWxE9Ld2JI+RJHHemd+E7DGO4/ec4vU2V2KQ4N5k5xGI7ehZW0qb+6/TxCKAFzDFMbKW4Y4mTxb/UXbHqEM+c8qX+D0vfH11/3NnR8Mn7JDnBMKdz7+Jf0Wiv0UU='), c => c.charCodeAt(0)).buffer,
                key_tag: 0
            } as RDATA[RecordType.DNSKEY]);
            expect(key.algorithm.name).to.eq('RSASSA-PKCS1-v1_5');
            expect(key.type).to.eq('public');
            expect(key.usages).to.include('verify');
            return expect(crypto.subtle.verify(ALGORITHMS[10], key, Uint8Array.from(atob('VfKcn15agCUifHL6pne6b4dajLAjzI99oml/Ddr2v/VFhIHY8e8Nq6+4i84EIvjd9GhyR7cnqgPE8RErLvNDzHDdL92yzyBZzojEfuYru1P5mHxN+unYqwY9s52dAQi2JItcdosN3p6By3jbEt2eYnWpa4D4EDmIpKqaFEf7sMEY5Z0jbDtByPcyWTWoqhYRih0h6HRh1ootKgDhDAt0PHP/JJxO2wdfFUM34alb8+uXNi0Mk53MMdCgpZBrYbPYGH9oxAQeXiZxrTvjv2RkE4Br3rUoUwpmEw3bgEXOCBS7jGSvnGtlewYEvchWs+I/kmVa6GDpduyGdVlT/Uar9w=='), c => c.charCodeAt(0)), Uint8Array.from("helloworld", c => c.charCodeAt(0)))).to.eventually.be.true;
        })
        it('should handle ECDSA P-256 SHA-256', async () => {
            // openssl ecparam -genkey -name prime256v1 -out key.pem
            // openssl pkey -pubout < key.pem | tail -n+2 | head -n-1 | tr -d '\n' | base64 -d | tail -c+28 | base64
            // -w0 | xclip and paste into the public key ( this rips the key out of asn1 format )
            // openssl dgst -sign key.pem -keyform PEM -sha384 -binary <<<"helloworld" | base64 -w0 | xclip and paste
            // into the sig string
            const key = await importDNSKEY({
                zone_key: true,
                secure_entry_point: false,
                protocol: 3,
                algorithm: 13,
                public_key: Uint8Array.from(atob('lSHdrTl4kEzS+bZASvPOpVN4RWxuyp3IwA22xczITXDRB285dI76hpKG/nFeAVqPB5YEaXz4Eu9HJenG2SE16Q=='), c => c.charCodeAt(0)).buffer,
                key_tag: 0
            } as RDATA[RecordType.DNSKEY]);
            expect(key.algorithm.name).to.eq('ECDSA');
            expect(key.type).to.eq('public');
            expect(key.usages).to.include('verify');
            return expect(crypto.subtle.verify(ALGORITHMS[13], key, Uint8Array.from(atob('MEQCIGjLQEwPMUgMG7Yymw46LHOUAd1PpqBgSZGg7ywlPHxkAiAOhX68D9R23vqT+rS5kCCtmtBiVyMki9a9/T8UxzdswQ=='), c => c.charCodeAt(0)), Uint8Array.from("helloworld", c => c.charCodeAt(0)))).to.eventually.be.true;
        })
        it('should handle ECDSA SHA-384', async () => {
            // openssl ecparam -genkey -name secp384r1 -out key.pem
            // openssl pkey -pubout < key.pem | tail -n+2 | head -n-1 | tr -d '\n' | base64 -d | tail -c+25 | base64
            // -w0 | xclip and paste into the public key ( this rips the key out of asn1 format )
            // openssl dgst -sign key.pem -keyform PEM -sha384 -binary <<<"helloworld" | base64 -w0 | xclip and paste
            // into the sig string
            const key = await importDNSKEY({
                zone_key: true,
                secure_entry_point: false,
                protocol: 3,
                algorithm: 14,
                public_key: Uint8Array.from(atob('8SDUWMY+0X2B42VERdUe71LBgTEAi45Im0mjIJ2i+kPlbr5DMU/zsYeD+GDbSf+YTyEh3SSuHxxLKTb0FBNDS/EqqcDAv/TfAKNEV36uaurIWH/M9QrC5ju2sY8dpL56'), c => c.charCodeAt(0)).buffer,
                key_tag: 0
            } as RDATA[RecordType.DNSKEY]);

            expect(key.algorithm.name).to.eq('ECDSA');
            expect(key.type).to.eq('public');
            expect(key.usages).to.include('verify');
            return expect(crypto.subtle.verify(ALGORITHMS[13], key, Uint8Array.from(atob('MGUCMGxQxrmUA2vcyKd8mo6hYYXcLZZJikZkcLx6jvOcB5MX4HFrLW2EpRJC4/pCchLEQgIxAJK8IM++WoT2QU74Lg+FtpoRUZBAm04gE4jVSDu8YHIPcQQj7oT5hQ3eeOQWYz8nHA=='), c => c.charCodeAt(0)), Uint8Array.from("helloworld", c => c.charCodeAt(0)))).to.eventually.be.true;
        })
    })

    describe('RRSIG signed data serialization', () => {
        it('should handle a base case', () => {
            expect(new Uint8Array(signedData({
                type_covered: RecordType.A,
                algorithm: 0,
                labels: 2,
                original_ttl: 1,
                sig_expiration: 0,
                sig_inception: 0,
                key_tag: 0,
                signer: ['authority', 'org', ''],
                signature: undefined
            }, [
                {
                    NAME: ['example', 'com', ''],
                    TYPE: RecordType.A,
                    CLASS: CLASS.IN,
                    TTL: 1,
                    RDLENGTH: 4,
                    RDATA: [0, 1, 2, 3],
                    raw_rdata: Uint8Array.from([0, 1, 2, 3]).buffer
                } as ResponseRecord<RecordType.A>
            ])).reduce((acc, cur) => acc + cur.toString(10).padStart(3, ' ') + ' ', '')).to.eq(Uint8Array.from([
                0, RecordType.A,                     // type_covered
                0,                                   // algorithm
                2,                                   // labels
                0, 0, 0, 1,                          // orig ttl
                0, 0, 0, 0,                          // sig exp
                0, 0, 0, 0,                          // sig inception
                0, 0,                                // key_tag
                9, 97, 117, 116, 104, 111, 114, 105, 116, 121, // 'authority'
                3, 111, 114, 103,                    // 'org'
                0,                                   // ''
                7, 101, 120, 97, 109, 112, 108, 101, // 'example'
                3, 99, 111, 109,                     // 'com'
                0,                                   // ''
                0, RecordType.A,
                0, CLASS.IN,
                0, 0, 0, 1,                         // TTL
                0, 4, 0, 1, 2, 3                    // RDLEN, RDATA
            ]).reduce((acc, cur) => acc + cur.toString(10).padStart(3, ' ') + ' ', ''))
        })
        it('should handle the signer being uppercase', () => {
            expect(new Uint8Array(signedData({
                type_covered: RecordType.A,
                algorithm: 0,
                labels: 2,
                original_ttl: 1,
                sig_expiration: 0,
                sig_inception: 0,
                key_tag: 0,
                signer: ['AUTHORITY', 'ORG', ''],
                signature: undefined
            }, [
                {
                    NAME: ['example', 'com', ''],
                    TYPE: RecordType.A,
                    CLASS: CLASS.IN,
                    TTL: 1,
                    RDLENGTH: 4,
                    RDATA: [0, 1, 2, 3],
                    raw_rdata: Uint8Array.from([0, 1, 2, 3]).buffer
                } as ResponseRecord<RecordType.A>
            ])).reduce((acc, cur) => acc + cur.toString(10).padStart(3, ' ') + ' ', '')).to.eq(Uint8Array.from([
                0, RecordType.A,                     // type_covered
                0,                                   // algorithm
                2,                                   // labels
                0, 0, 0, 1,                          // orig ttl
                0, 0, 0, 0,                          // sig exp
                0, 0, 0, 0,                          // sig inception
                0, 0,                                // key_tag
                9, 97, 117, 116, 104, 111, 114, 105, 116, 121, // 'authority'
                3, 111, 114, 103,                    // 'org'
                0,                                   // ''
                7, 101, 120, 97, 109, 112, 108, 101, // 'example'
                3, 99, 111, 109,                     // 'com'
                0,                                   // ''
                0, RecordType.A,
                0, CLASS.IN,
                0, 0, 0, 1,                         // TTL
                0, 4, 0, 1, 2, 3                    // RDLEN, RDATA
            ]).reduce((acc, cur) => acc + cur.toString(10).padStart(3, ' ') + ' ', ''))
        })
        it('should handle the signer missing the null terminator', () => {
            expect(() => signedData({
                type_covered: RecordType.A,
                algorithm: 0,
                labels: 2,
                original_ttl: 1,
                sig_expiration: 0,
                sig_inception: 0,
                key_tag: 0,
                signer: ['AUTHORITY', 'ORG'],
                signature: undefined
            }, [
                {
                    NAME: ['example', 'com', ''],
                    TYPE: RecordType.A,
                    CLASS: CLASS.IN,
                    TTL: 1,
                    RDLENGTH: 4,
                    RDATA: [0, 1, 2, 3],
                    raw_rdata: Uint8Array.from([0, 1, 2, 3]).buffer
                } as ResponseRecord<RecordType.A>
            ])).to.throw('Signer not well formed');
        })
        it('should handle the rrset being out of order', () => {
            expect(new Uint8Array(signedData({
                type_covered: RecordType.A,
                algorithm: 0,
                labels: 2,
                original_ttl: 1,
                sig_expiration: 0,
                sig_inception: 0,
                key_tag: 0,
                signer: ['authority', 'org', ''],
                signature: undefined
            }, [
                {
                    NAME: ['example', 'com', ''],
                    TYPE: RecordType.A,
                    CLASS: CLASS.IN,
                    TTL: 1,
                    RDLENGTH: 4,
                    RDATA: [10, 1, 2, 3],
                    raw_rdata: Uint8Array.from([10, 1, 2, 3]).buffer
                } as ResponseRecord<RecordType.A>,
                {
                    NAME: ['example', 'com', ''],
                    TYPE: RecordType.A,
                    CLASS: CLASS.IN,
                    TTL: 1,
                    RDLENGTH: 4,
                    RDATA: [0, 1, 2, 3],
                    raw_rdata: Uint8Array.from([0, 1, 2, 3]).buffer
                } as ResponseRecord<RecordType.A>,
            ])).reduce((acc, cur) => acc + cur.toString(10).padStart(3, ' ') + ' ', '')).to.eq(Uint8Array.from([
                0, RecordType.A,                     // type_covered
                0,                                   // algorithm
                2,                                   // labels
                0, 0, 0, 1,                          // orig ttl
                0, 0, 0, 0,                          // sig exp
                0, 0, 0, 0,                          // sig inception
                0, 0,                                // key_tag
                9, 97, 117, 116, 104, 111, 114, 105, 116, 121, // 'authority'
                3, 111, 114, 103,                    // 'org'
                0,                                   // ''
                7, 101, 120, 97, 109, 112, 108, 101, // 'example'
                3, 99, 111, 109,                     // 'com'
                0,                                   // ''
                0, RecordType.A,
                0, CLASS.IN,
                0, 0, 0, 1,                         // TTL
                0, 4, 0, 1, 2, 3,                    // RDLEN, RDATA
                7, 101, 120, 97, 109, 112, 108, 101, // 'example'
                3, 99, 111, 109,                     // 'com'
                0,                                   // ''
                0, RecordType.A,
                0, CLASS.IN,
                0, 0, 0, 1,                         // TTL
                0, 4, 10, 1, 2, 3,                    // RDLEN, RDATA
            ]).reduce((acc, cur) => acc + cur.toString(10).padStart(3, ' ') + ' ', ''))
        })
        it('should handle the rrset being out of order with a variable length record type', () => {
            expect(new Uint8Array(signedData({
                type_covered: RecordType.CNAME,
                algorithm: 0,
                labels: 2,
                original_ttl: 1,
                sig_expiration: 0,
                sig_inception: 0,
                key_tag: 0,
                signer: ['authority', 'org', ''],
                signature: undefined
            }, [
                {
                    NAME: ['example', 'com', ''],
                    TYPE: RecordType.CNAME,
                    CLASS: CLASS.IN,
                    TTL: 1,
                    RDLENGTH: 10,
                    RDATA: ['example2', ''],
                    raw_rdata: Uint8Array.from([8, 101, 120, 97, 109, 112, 108, 101, 50, 0]).buffer
                } as ResponseRecord<RecordType.CNAME>,
                {
                    NAME: ['example', 'com', ''],
                    TYPE: RecordType.CNAME,
                    CLASS: CLASS.IN,
                    TTL: 1,
                    RDLENGTH: 9,
                    RDATA: ['example', ''],
                    raw_rdata: Uint8Array.from([7, 101, 120, 97, 109, 112, 108, 101, 0]).buffer
                } as ResponseRecord<RecordType.CNAME>,
                {
                    NAME: ['example', 'com', ''],
                    TYPE: RecordType.CNAME,
                    CLASS: CLASS.IN,
                    TTL: 1,
                    RDLENGTH: 10,
                    RDATA: ['\x02xample2', ''],
                    raw_rdata: Uint8Array.from([8, 2, 120, 97, 109, 112, 108, 101, 50, 0]).buffer
                } as ResponseRecord<RecordType.CNAME>,
            ])).reduce((acc, cur) => acc + cur.toString(10).padStart(3, ' ') + ' ', '')).to.eq(Uint8Array.from([
                0, RecordType.CNAME,                     // type_covered
                0,                                   // algorithm
                2,                                   // labels
                0, 0, 0, 1,                          // orig ttl
                0, 0, 0, 0,                          // sig exp
                0, 0, 0, 0,                          // sig inception
                0, 0,                                // key_tag
                9, 97, 117, 116, 104, 111, 114, 105, 116, 121, // 'authority'
                3, 111, 114, 103,                    // 'org'
                0,                                   // ''
                // ---
                7, 101, 120, 97, 109, 112, 108, 101, // 'example'
                3, 99, 111, 109,                     // 'com'
                0,                                   // ''
                0, RecordType.CNAME,
                0, CLASS.IN,
                0, 0, 0, 1,                         // TTL
                0, 9, 7, 101, 120, 97, 109, 112, 108, 101, 0, // RDLEN, RDATA
                // ---
                7, 101, 120, 97, 109, 112, 108, 101, // 'example'
                3, 99, 111, 109,                     // 'com'
                0,                                   // ''
                0, RecordType.CNAME,
                0, CLASS.IN,
                0, 0, 0, 1,                         // TTL
                0, 10, 8, 2, 120, 97, 109, 112, 108, 101, 50, 0, // RDLEN, RDATA
                // ---
                7, 101, 120, 97, 109, 112, 108, 101, // 'example'
                3, 99, 111, 109,                     // 'com'
                0,                                   // ''
                0, RecordType.CNAME,
                0, CLASS.IN,
                0, 0, 0, 1,                         // TTL
                0, 10, 8, 101, 120, 97, 109, 112, 108, 101, 50, 0, // RDLEN, RDATA
            ]).reduce((acc, cur) => acc + cur.toString(10).padStart(3, ' ') + ' ', ''))
        })
        it('should handle the RRSet NAME being uppercase', () => {
            expect(new Uint8Array(signedData({
                type_covered: RecordType.A,
                algorithm: 0,
                labels: 2,
                original_ttl: 1,
                sig_expiration: 0,
                sig_inception: 0,
                key_tag: 0,
                signer: ['authority', 'org', ''],
                signature: undefined
            }, [
                {
                    NAME: ['example', 'com', ''],
                    TYPE: RecordType.A,
                    CLASS: CLASS.IN,
                    TTL: 1,
                    RDLENGTH: 4,
                    RDATA: [0, 1, 2, 3],
                    raw_rdata: Uint8Array.from([0, 1, 2, 3]).buffer
                } as ResponseRecord<RecordType.A>
            ])).reduce((acc, cur) => acc + cur.toString(10).padStart(3, ' ') + ' ', '')).to.eq(Uint8Array.from([
                0, RecordType.A,                     // type_covered
                0,                                   // algorithm
                2,                                   // labels
                0, 0, 0, 1,                          // orig ttl
                0, 0, 0, 0,                          // sig exp
                0, 0, 0, 0,                          // sig inception
                0, 0,                                // key_tag
                9, 97, 117, 116, 104, 111, 114, 105, 116, 121, // 'authority'
                3, 111, 114, 103,                    // 'org'
                0,                                   // ''
                7, 101, 120, 97, 109, 112, 108, 101, // 'example'
                3, 99, 111, 109,                     // 'com'
                0,                                   // ''
                0, RecordType.A,
                0, CLASS.IN,
                0, 0, 0, 1,                         // TTL
                0, 4, 0, 1, 2, 3                    // RDLEN, RDATA
            ]).reduce((acc, cur) => acc + cur.toString(10).padStart(3, ' ') + ' ', ''))
        })
        it('should handle the RRSet TTL being different from the original', () => {
            expect(new Uint8Array(signedData({
                type_covered: RecordType.A,
                algorithm: 0,
                labels: 2,
                original_ttl: 1,
                sig_expiration: 0,
                sig_inception: 0,
                key_tag: 0,
                signer: ['authority', 'org', ''],
                signature: undefined
            }, [
                {
                    NAME: ['example', 'com', ''],
                    TYPE: RecordType.A,
                    CLASS: CLASS.IN,
                    TTL: 2,
                    RDLENGTH: 4,
                    RDATA: [0, 1, 2, 3],
                    raw_rdata: Uint8Array.from([0, 1, 2, 3]).buffer
                } as ResponseRecord<RecordType.A>
            ])).reduce((acc, cur) => acc + cur.toString(10).padStart(3, ' ') + ' ', '')).to.eq(Uint8Array.from([
                0, RecordType.A,                     // type_covered
                0,                                   // algorithm
                2,                                   // labels
                0, 0, 0, 1,                          // orig ttl
                0, 0, 0, 0,                          // sig exp
                0, 0, 0, 0,                          // sig inception
                0, 0,                                // key_tag
                9, 97, 117, 116, 104, 111, 114, 105, 116, 121, // 'authority'
                3, 111, 114, 103,                    // 'org'
                0,                                   // ''
                7, 101, 120, 97, 109, 112, 108, 101, // 'example'
                3, 99, 111, 109,                     // 'com'
                0,                                   // ''
                0, RecordType.A,
                0, CLASS.IN,
                0, 0, 0, 1,                         // TTL
                0, 4, 0, 1, 2, 3                    // RDLEN, RDATA
            ]).reduce((acc, cur) => acc + cur.toString(10).padStart(3, ' ') + ' ', ''))
        })
        it('should handle a RRSets with more labels than the RRSIG labels field', () => {
            expect(new Uint8Array(signedData({
                type_covered: RecordType.A,
                algorithm: 0,
                labels: 2,
                original_ttl: 1,
                sig_expiration: 0,
                sig_inception: 0,
                key_tag: 0,
                signer: ['authority', 'org', ''],
                signature: undefined
            }, [
                {
                    NAME: ['dub', 'sub', 'example', 'com', ''],
                    TYPE: RecordType.A,
                    CLASS: CLASS.IN,
                    TTL: 1,
                    RDLENGTH: 4,
                    RDATA: [0, 1, 2, 3],
                    raw_rdata: Uint8Array.from([0, 1, 2, 3]).buffer
                } as ResponseRecord<RecordType.A>
            ])).reduce((acc, cur) => acc + cur.toString(10).padStart(3, ' ') + ' ', '')).to.eq(Uint8Array.from([
                0, RecordType.A,                     // type_covered
                0,                                   // algorithm
                2,                                   // labels
                0, 0, 0, 1,                          // orig ttl
                0, 0, 0, 0,                          // sig exp
                0, 0, 0, 0,                          // sig inception
                0, 0,                                // key_tag
                9, 97, 117, 116, 104, 111, 114, 105, 116, 121, // 'authority'
                3, 111, 114, 103,                    // 'org'
                0,                                   // ''
                1, 42,                               // '*'
                7, 101, 120, 97, 109, 112, 108, 101, // 'example'
                3, 99, 111, 109,                     // 'com'
                0,                                   // ''
                0, RecordType.A,
                0, CLASS.IN,
                0, 0, 0, 1,                         // TTL
                0, 4, 0, 1, 2, 3                    // RDLEN, RDATA
            ]).reduce((acc, cur) => acc + cur.toString(10).padStart(3, ' ') + ' ', ''))
        })
        it('should handle RRSets with less labels than the RRSIG labels field', () => {
            expect(() => signedData({
                type_covered: RecordType.A,
                algorithm: 0,
                labels: 2,
                original_ttl: 1,
                sig_expiration: 0,
                sig_inception: 0,
                key_tag: 0,
                signer: ['authority', 'org', ''],
                signature: undefined
            }, [
                {
                    NAME: ['com', ''],
                    TYPE: RecordType.A,
                    CLASS: CLASS.IN,
                    TTL: 1,
                    RDLENGTH: 4,
                    RDATA: [0, 1, 2, 3],
                    raw_rdata: Uint8Array.from([0, 1, 2, 3]).buffer
                } as ResponseRecord<RecordType.A>
            ])).to.throw('higher level domain');
        })
        it('should reject RRSets that dont match the RRSIG type covered', () => {
            expect(() => signedData({
                type_covered: RecordType.A,
                algorithm: 0,
                labels: 2,
                original_ttl: 1,
                sig_expiration: 0,
                sig_inception: 0,
                key_tag: 0,
                signer: ['authority', 'org', ''],
                signature: undefined
            }, [
                {
                    NAME: ['example', 'com', ''],
                    TYPE: RecordType.A,
                    CLASS: CLASS.IN,
                    TTL: 1,
                    RDLENGTH: 4,
                    RDATA: [0, 1, 2, 3],
                    raw_rdata: Uint8Array.from([0, 1, 2, 3]).buffer
                } as ResponseRecord<RecordType.A>,
                {
                    NAME: ['example', 'com', ''],
                    TYPE: RecordType.CNAME,
                    CLASS: CLASS.IN,
                    TTL: 1,
                    RDLENGTH: 4,
                    RDATA: ['foo', 'bar', ''],
                    raw_rdata: Uint8Array.from([3, 102, 111, 111, 3, 10, 98, 97, 114, 0]).buffer
                } as ResponseRecord<RecordType.CNAME>
            ])).to.throw('does not match the RRSIG type covered');
        })
        xit('should handle a CNAME RRSet with uppercase names in their RDATA') // TODO
    })

    describe('RRSIG validation', () => {
        let key: CryptoKeyPair;
        const alg = 13;
        const rrsigData = {
            algorithm: alg,
            key_tag: 0,
            labels: 2,
            original_ttl: 1,
            sig_expiration: 0,
            sig_inception: 0,
            signature: undefined,
            signer: ['authority', 'org', ''],
            type_covered: RecordType.A
        } as RDATA[RecordType.RRSIG];
        const rrset = [
            {
                NAME: ['example', 'com', ''],
                TYPE: RecordType.A,
                CLASS: CLASS.IN,
                TTL: 1,
                RDLENGTH: 4,
                RDATA: [0, 1, 2, 3],
                raw_rdata: Uint8Array.from([0, 1, 2, 3]).buffer
            } as ResponseRecord<RecordType.A>
        ];
        before("generate test data", async () => {
            key = await crypto.subtle.generateKey(ALGORITHMS[alg], false, ["sign", "verify"]) as CryptoKeyPair;
            rrsigData.signature = await crypto.subtle.sign(ALGORITHMS[alg], key.privateKey, signedData(rrsigData, rrset));
        })
        it('should handle a single provided key', async () => {
            expect(await verifyRRSIG([key.publicKey], rrsigData, rrset)).to.be.true;
        })
        it('should handle no key provided being as valid key', async () => {
            const key2 = await crypto.subtle.generateKey(ALGORITHMS[alg], false, ["sign", "verify"]) as CryptoKeyPair;
            expect(await verifyRRSIG([key2.publicKey], rrsigData, rrset)).to.be.false;
        })
        it('should handle an empty list of keys', async () => {
            expect(await verifyRRSIG([], rrsigData, rrset)).to.be.false;
        })
        it('should handle multiple valid keys', async () => {
            expect(await verifyRRSIG([key.publicKey, key.publicKey], rrsigData, rrset)).to.be.true;
        })
        it('should handle an unexpected algorithm', async () => {
            return expect(verifyRRSIG([key.publicKey], {
                ...rrsigData,
                algorithm: 0
            }, rrset)).to.eventually.be.rejectedWith("unsupported algorithm");
        })
        it('should handle an invalid sig', async () => {
            expect(await verifyRRSIG([key.publicKey], {
                ...rrsigData,
                signature: Uint8Array.from("fake sig", c => c.charCodeAt(0)).buffer
            }, rrset)).to.be.false;
        })
    })

    // eslint-disable-next-line:no-empty
    async function fakeRootTrustAnchor(fetchCallback = () => {
    }, algorithm = 13) {
        const key = await (crypto.subtle.generateKey(ALGORITHMS[algorithm], true, ["verify", "sign"]) as Promise<CryptoKeyPair>);
        const pubkey = await crypto.subtle.exportKey('raw', key.publicKey);
        const digestData = [
            0,                                   // ''
            256,                                 // flags
            3,                                   // protocol
            13,                                  // algorithm
            ...new Uint8Array(pubkey),
        ];
        const fakeTrustAnchorDoc = `<TrustAnchor>
<Zone>.</Zone>
<KeyDigest id="Kjqmt7v" validFrom="2010-07-15T00:00:00+00:00">
<KeyTag>0</KeyTag>
<Algorithm>13</Algorithm>
<DigestType>2</DigestType>
<Digest>
${Array.from(new Uint8Array(await crypto.subtle.digest(DIGESTS[2], Uint8Array.from(digestData).buffer)), b => b.toString(16).padStart(2, '0')).join('')}
</Digest>
</KeyDigest>
</TrustAnchor>`
        setFetch(async (url) => {
            fetchCallback();
            expect(url).to.eq("https://data.iana.org/root-anchors/root-anchors.xml");
            return new Response(fakeTrustAnchorDoc);
        });
        return {
            NAME: [''],
            TTL: 60,
            CLASS: CLASS.IN,
            TYPE: RecordType.DNSKEY,
            RDATA: {
                algorithm,
                key_tag: 0,
                secure_entry_point: false,
                zone_key: true,
                protocol: 3,
                public_key: pubkey,
            },
            RDLENGTH: 4 + pubkey.byteLength,
            raw_rdata: Uint8Array.from([
                256,                                 // flags
                3,                                   // protocol
                13,                                  // algorithm
                ...new Uint8Array(pubkey)
            ]).buffer,
        } as ResponseRecord<RecordType.DNSKEY>;
    }

    class FakeResolver extends BaseResolver {
        public keys: Record<string, CryptoKeyPair>;
        public pubkeys: Record<string, ArrayBuffer>;
        public ttl = 10;
        public called = 0;
        public expectedHostname?: string = undefined;
        public responseCallback = (response: DNSResponse) => response;

        public static async build(domains: string[], algorithm: number = 13) {
            const resolver = new this();
            const keys = await Promise.all(domains.map(domain => crypto.subtle.generateKey(ALGORITHMS[algorithm], true, ["verify", "sign"]) as Promise<CryptoKeyPair>));
            resolver.keys = Object.fromEntries(domains.map((domain, i) => [domain, keys[i]]));
            const pubkeysData = await Promise.all(Object.values(keys).map((v) => crypto.subtle.exportKey('raw', v.publicKey)));
            resolver.pubkeys = Object.fromEntries(pubkeysData.map((v, i) => [domains[i], v]));
            return resolver;
        }

        cancel(): void {
            throw new Error('Method not implemented.');
        }

        async resolve(hostname: string | {
            hostname: string,
            rrtype: (keyof typeof RecordType)
        }[], rrtype?: (keyof typeof RecordType) | "ANY" | ResolveOptions, options?: ResolveOptions): Promise<any> {
            this.called += 1;
            expect(rrtype).to.be.oneOf(["DS", "DNSKEY"]);
            expect(options.dnssec, 'DNSSEC must be enabled').to.be.true;
            expect(options.raw, 'Raw response expected').to.be.true;
            expect(typeof hostname, 'hostname is not a string').to.eq('string');
            const trimmedHostname = (hostname as string).replace(/\.$/, '').toLowerCase();
            expect(this.pubkeys).to.haveOwnProperty(trimmedHostname);
            if (this.expectedHostname) expect(hostname, 'unexpected hostname when requesting DS for KSK').to.eq(this.expectedHostname);
            switch (rrtype) {
                case "DS":


                    // digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
                    // DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.  "|" denotes concatenation
                    const digestData = [
                        ...trimmedHostname.split('.').flatMap(s => [s.length, ...Uint8Array.from(s, c => c.charCodeAt(0))]),
                        0,                                   // ''
                        256,                                 // flags
                        3,                                   // protocol
                        13,                                  // algorithm
                        ...new Uint8Array(this.pubkeys[trimmedHostname]),
                    ];
                    const rdata = {
                        key_tag: 0,
                        algorithm: 13,
                        digest_type: 2,
                        digest: await crypto.subtle.digest(DIGESTS[2], Uint8Array.from(digestData).buffer),
                    } as RDATA[RecordType.DS];
                    return this.responseCallback({
                        header: {},
                        question: [{} as Question],
                        answer: [{
                            NAME: [...trimmedHostname.split('.'), ''],
                            TYPE: RecordType.DS,
                            CLASS: CLASS.IN,
                            TTL: this.ttl,
                            RDATA: rdata,
                            RDLENGTH: 4 + rdata.digest.byteLength,
                            raw_rdata: Uint8Array.from([0, rdata.key_tag, rdata.algorithm, rdata.digest_type, ...new Uint8Array(rdata.digest)]).buffer
                        } as AnswerRecord<RecordType.DS>],
                        additional: [],
                        authority: [],
                    } as DNSResponse);
                case "DNSKEY":
                    return this.responseCallback({
                        header: {},
                        question: [{} as Question],
                        answer: [{
                            NAME: [...trimmedHostname.split('.'), ''],
                            TYPE: RecordType.DNSKEY,
                            CLASS: CLASS.IN,
                            TTL: this.ttl,
                            RDATA: {
                                key_tag: 0,
                                algorithm: 13,
                                protocol: 3,
                                zone_key: true,
                                secure_entry_point: false,
                                public_key: this.pubkeys[trimmedHostname],
                            },
                            RDLENGTH: 4 + this.pubkeys[trimmedHostname].byteLength,
                            raw_rdata: Uint8Array.from([256, 3, 13, ...new Uint8Array(this.pubkeys[trimmedHostname])]).buffer
                        } as AnswerRecord<RecordType.DNSKEY>],
                        additional: [],
                        authority: [],
                    } as DNSResponse);
            }
        }

        protected servers: string[];
    }

    describe('KSK validation', () => {
        const alg = 13;
        let resolver: FakeResolver;
        const dummyRootKSK = {
            NAME: [''],
            CLASS: CLASS.IN,
            TTL: 0,
            TYPE: RecordType.DNSKEY,
            RDLENGTH: 3,
            RDATA: {
                algorithm: 13,
                key_tag: 0,
                protocol: 3,
                public_key: undefined,
                secure_entry_point: false,
                zone_key: true
            },
            raw_rdata: Uint8Array.from("foo", c => c.charCodeAt(0)).buffer,
        } as ResponseRecord<RecordType.DNSKEY>;
        const realTrustAnchorDoc = `<TrustAnchor id="0C05FDD6-422C-4910-8ED6-430ED15E11C2" source="http://data.iana.org/root-anchors/root-anchors.xml">
<Zone>.</Zone>
<KeyDigest id="Kjqmt7v" validFrom="2010-07-15T00:00:00+00:00" validUntil="2019-01-11T00:00:00+00:00">
<KeyTag>19036</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>
49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5
</Digest>
</KeyDigest>
<KeyDigest id="Klajeyz" validFrom="2017-02-02T00:00:00+00:00">
<KeyTag>20326</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>
E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
</Digest>
<PublicKey>
AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
</PublicKey>
<Flags>257</Flags>
</KeyDigest>
<KeyDigest id="Kmyv6jo" validFrom="2024-07-18T00:00:00+00:00">
<KeyTag>38696</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>
683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
</Digest>
<PublicKey>
AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=
</PublicKey>
<Flags>257</Flags>
</KeyDigest>
</TrustAnchor>`;
        const expiredTrustAnchorDoc = `<TrustAnchor id="0C05FDD6-422C-4910-8ED6-430ED15E11C2" source="http://data.iana.org/root-anchors/root-anchors.xml">
<Zone>.</Zone>
<KeyDigest id="Kjqmt7v" validFrom="2010-07-15T00:00:00+00:00" validUntil="2019-01-11T00:00:00+00:00">
<KeyTag>19036</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>
49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5
</Digest>
</KeyDigest>
<KeyDigest id="Klajeyz" validFrom="2017-02-02T00:00:00+00:00" validUntil="2020-07-18T00:00:00+00:00">
<KeyTag>20326</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>
E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
</Digest>
<PublicKey>
AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
</PublicKey>
<Flags>257</Flags>
</KeyDigest>
<KeyDigest id="Kmyv6jo" validFrom="2024-07-18T00:00:00+00:00" validUntil="2020-07-18T00:00:00+00:00">
<KeyTag>38696</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>
683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
</Digest>
<PublicKey>
AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=
</PublicKey>
<Flags>257</Flags>
</KeyDigest>
</TrustAnchor>`;
        let fakeKSK: Record<string, AnswerRecord<RecordType.DNSKEY>>;
        beforeEach('set up resolver and test KSK', async () => {
            clearCaches();
            resolver = await FakeResolver.build(['com', 'example.com']);
            fakeKSK = Object.fromEntries(Object.entries(resolver.pubkeys).map(([k, v]) => [k, {
                NAME: [...(k + '.').split('.')],
                TTL: 60,
                CLASS: CLASS.IN,
                TYPE: RecordType.DNSKEY,
                RDATA: {
                    algorithm: alg,
                    key_tag: 0,
                    secure_entry_point: false,
                    zone_key: true,
                    protocol: 3,
                    public_key: v,
                },
                RDLENGTH: 4 + v.byteLength,
                raw_rdata: Uint8Array.from([
                    256,                                 // flags
                    3,                                   // protocol
                    13,                                  // algorithm
                    ...new Uint8Array(v)
                ]).buffer,
            }]));
        })
        afterEach('restore fetch', restoreFetch)
        afterEach('clean fakeKSK', () => {
            fakeKSK = undefined;
            resolver = undefined;
        })
        it('fetch should be hooked for tests', async () => {
            const sentinel = {} as Response;
            setFetch(async () => sentinel);
            expect(await fetch(''), 'fetch is not hooked').to.eq(sentinel);
        })
        it('should validate against the root', async () => {
            let called = false;
            const rootKSK = await fakeRootTrustAnchor(() => called = true);
            expect(await validateKSK(rootKSK, resolver), 'KSK invalid').to.be.true;
            expect(called, 'fetch not called').to.be.true;
        })
        it('should ensure only zone keys are validated', () => {
            return expect(validateKSK({
                ...dummyRootKSK,
                RDATA: {...dummyRootKSK.RDATA, zone_key: false}
            }, resolver)).to.eventually.be.false;
        })
        it('should validate non-root domains', async () => {
            let called = false;
            await fakeRootTrustAnchor(() => called = true);
            expect(await validateKSK(fakeKSK['example.com'], resolver), 'KSK invalid').to.be.true;
            expect(called, 'fetch not called').to.be.false;
        })
        it('should handle DS existing for the domain but no matching DS for the KSK', async () => {
            let called = false;
            await fakeRootTrustAnchor(() => called = true);
            const ksk = fakeKSK['example.com'];
            expect(await validateKSK(ksk, resolver), 'KSK invalid').to.be.true;
            ksk.RDATA.key_tag = 1;
            expect(await validateKSK(ksk, resolver), 'KSK not rejected for non-matching key_tag').to.be.false;
            ksk.RDATA.key_tag = 0;
            ksk.RDATA.algorithm = 0;
            expect(await validateKSK(ksk, resolver), 'KSK not rejected for non-matching algorithm').to.be.false;
            ksk.RDATA.algorithm = 13;
            ksk.RDATA.public_key = resolver.pubkeys.com;
            ksk.raw_rdata = fakeKSK.com.raw_rdata;
            expect(await validateKSK(ksk, resolver), 'KSK not rejected for non-matching pubkey').to.be.false;
            expect(called, 'fetch called').to.be.false;
        })
        it('should handle repeated digest types/DS records', async () => {
            let called = false;
            await fakeRootTrustAnchor(() => called = true);
            resolver.responseCallback = (resp) => {
                resp.answer = [resp.answer[0], resp.answer[0]];
                return resp;
            }
            expect(await validateKSK(fakeKSK['example.com'], resolver), 'KSK invalid').to.be.true;
            expect(called, 'fetch not called').to.be.false;
        })
        it('should handle the KSK name being uppercase', async () => {
            let called = false;
            await fakeRootTrustAnchor(() => called = true);
            const ksk = fakeKSK['example.com'];
            ksk.NAME = ksk.NAME.map(s => s.toUpperCase())
            expect(await validateKSK(ksk, resolver), 'failed to handle uppercase name').to.be.true;
            expect(called, 'fetch not called').to.be.false;
        })
        it('should reject a KSK with a unexpected protocol', async () => {
            let called = false;
            await fakeRootTrustAnchor(() => called = true);
            const ksk = fakeKSK['example.com'];
            ksk.RDATA.protocol = 0;
            expect(await validateKSK(ksk, resolver), 'failed to reject unknown protocol').to.be.false;
            expect(called, 'fetch not called').to.be.false;
        })
        it('should handle the KSK raw_rdata not being populated', () => {
            return expect(validateKSK({
                ...dummyRootKSK,
                raw_rdata: undefined
            }, resolver)).to.eventually.be.rejectedWith('raw_rdata');
        })
        describe('fetching DS', () => { // test the unexposed getStoredDS via validateKSK
            it('should handle all cached DS being expired', async () => {
                let called = false;
                await fakeRootTrustAnchor(() => called = true);
                resolver.ttl = 0;
                expect(await validateKSK(fakeKSK.com, resolver), 'KSK invalid').to.be.true;
                expect(await validateKSK(fakeKSK.com, resolver), 'KSK invalid').to.be.true;
                expect(resolver.called, 'resolve not called twice due to cache expiry').to.eq(2);
                expect(called, 'fetch called').to.be.false;
            })
            it('should cache DS records', async () => {
                let called = false;
                await fakeRootTrustAnchor(() => called = true);
                resolver.ttl = 10;
                expect(await validateKSK(fakeKSK.com, resolver), 'KSK invalid').to.be.true;
                expect(await validateKSK(fakeKSK.com, resolver), 'KSK invalid').to.be.true;
                expect(resolver.called, 'resolve called twice due to not caching').to.eq(1);
                expect(called, 'fetch called').to.be.false;
            })
            it('should request DS records for the appropriate domain', async () => {
                let called = false;
                await fakeRootTrustAnchor(() => called = true);
                resolver.ttl = 10;
                resolver.expectedHostname = 'example.com.';
                expect(await validateKSK(fakeKSK['example.com'], resolver), 'KSK invalid').to.be.true;
                expect(called, 'fetch called').to.be.false;
            })
        })

        describe('fetching root digests', () => { // test the unexposed getStoredDS and getRootDS via validateKSK
            it('should fetch the root digests from IANA', async () => {
                let called = false;
                setFetch(async (url) => {
                    called = true;
                    expect(url).to.eq("https://data.iana.org/root-anchors/root-anchors.xml");
                    return new Response(realTrustAnchorDoc);
                });
                await validateKSK(dummyRootKSK, resolver);
                expect(called, 'fetch not called').to.be.true;
            })
            it('should validate that the returned digests are for the correct zone', async () => {
                let called = false;
                setFetch(async (url) => {
                    called = true;
                    expect(url).to.eq("https://data.iana.org/root-anchors/root-anchors.xml");
                    return new Response(`<TrustAnchor><Zone>ca.</Zone></TrustAnchor>`);
                });
                await expect(validateKSK(dummyRootKSK, resolver), 'KSK invalid').to.eventually.be.rejectedWith('Unexpected zone');
                expect(called, 'fetch not called').to.be.true;
            })
            it('should handle invalid IANA response', async () => {
                let called = false;
                setFetch(async (url) => {
                    called = true;
                    expect(url).to.eq("https://data.iana.org/root-anchors/root-anchors.xml");
                    return new Response('test');
                });
                await expect(validateKSK(dummyRootKSK, resolver), 'KSK invalid').to.eventually.be.rejectedWith('Unable to parse');
                expect(called, 'fetch not called').to.be.true;
            })
            it('should cache ROOT digests', async () => {
                let called = false;
                setFetch(async (url) => {
                    called = true;
                    expect(url).to.eq("https://data.iana.org/root-anchors/root-anchors.xml");
                    return new Response(realTrustAnchorDoc);
                });
                await validateKSK(dummyRootKSK, resolver);
                expect(called, 'fetch not called').to.be.true;
                called = false;
                setFetch(async (url) => {
                    called = true;
                    assert.fail('the trust anchor was not cached');
                    return new Response(realTrustAnchorDoc);
                });
                await validateKSK(dummyRootKSK, resolver);
                expect(called, 'fetch called twice').to.be.false;
            })
            it('should handle all root digests being expired', async () => {
                let called = false;
                setFetch(async (url) => {
                    called = true;
                    expect(url).to.eq("https://data.iana.org/root-anchors/root-anchors.xml");
                    return new Response(expiredTrustAnchorDoc);
                });
                expect(await validateKSK(dummyRootKSK, resolver)).to.be.false;
                expect(called, 'fetch not called').to.be.true;
            })
        })
    })

    describe('validate RRSet against RRSIG', () => {
        let resolver: FakeResolver;
        let ARecord: ResponseRecord<RecordType.A>;
        let DNSKEYRecord: ResponseRecord<RecordType.DNSKEY>;
        let ZONEKEY: ResponseRecord<RecordType.DNSKEY>;
        let CNAMERecord: ResponseRecord<RecordType.CNAME>;
        let TXTRecord: ResponseRecord<RecordType.TXT>;
        let ARRSIG: ResponseRecord<RecordType.RRSIG>;
        let CNAMERRSIG: ResponseRecord<RecordType.RRSIG>;
        let TXTRRSIG: ResponseRecord<RecordType.RRSIG>;
        let DNSKEYRRSIG: ResponseRecord<RecordType.RRSIG>;
        beforeEach('set up', async () => {
            clearCaches();
            resolver = await FakeResolver.build(['com', 'example.com', 'sub.example.com', 'subexample.com']);

            ARecord = {
                NAME: ['example', 'com', ''],
                TYPE: RecordType.A,
                CLASS: CLASS.IN,
                TTL: 10,
                RDATA: [1, 2, 3, 4],
                raw_rdata: Uint8Array.from([0, 1, 2, 3]).buffer,
                RDLENGTH: 4,
            };
            CNAMERecord = {
                NAME: ['example', 'com', ''],
                TYPE: RecordType.CNAME,
                CLASS: CLASS.IN,
                TTL: 10,
                RDATA: ['foo', 'bar', ''],
                raw_rdata: Uint8Array.from([3, 102, 111, 111, 3, 10, 98, 97, 114, 0]).buffer,
                RDLENGTH: 10,
            };
            TXTRecord = {
                NAME: ['example', 'com', ''],
                TYPE: RecordType.TXT,
                CLASS: CLASS.IN,
                TTL: 10,
                RDATA: ['foo', 'bar', ''],
                raw_rdata: Uint8Array.from([3, 102, 111, 111, 3, 10, 98, 97, 114, 0]).buffer,
                RDLENGTH: 10,
            };
            ZONEKEY = {
                NAME: ['example', 'com', ''],
                TYPE: RecordType.DNSKEY,
                CLASS: CLASS.IN,
                TTL: 10,
                RDATA: {
                    key_tag: 0,
                    protocol: 3,
                    zone_key: true,
                    algorithm: 13,
                    public_key: resolver.pubkeys['example.com'],
                    secure_entry_point: false,
                } as RDATA[RecordType.DNSKEY],
                RDLENGTH: 4 + resolver.pubkeys['example.com'].byteLength,
                raw_rdata: Uint8Array.from([
                    256,                                 // flags
                    3,                                   // protocol
                    13,                                  // algorithm
                    ...new Uint8Array(resolver.pubkeys['example.com'])
                ]).buffer,
            };
            DNSKEYRecord = {
                NAME: ['example', 'com', ''],
                TYPE: RecordType.DNSKEY,
                CLASS: CLASS.IN,
                TTL: 10,
                RDATA: {
                    key_tag: 1,
                    protocol: 3,
                    zone_key: false,
                    algorithm: 13,
                    public_key: resolver.pubkeys['example.com'],
                    secure_entry_point: false,
                } as RDATA[RecordType.DNSKEY],
                RDLENGTH: 4 + resolver.pubkeys['example.com'].byteLength,
                raw_rdata: Uint8Array.from([
                    256,                                 // flags
                    3,                                   // protocol
                    13,                                  // algorithm
                    ...new Uint8Array(resolver.pubkeys['example.com'])
                ]).buffer,
            };
            ARRSIG = {
                NAME: ['example', 'com', ''],
                TYPE: RecordType.RRSIG,
                CLASS: CLASS.IN,
                TTL: 10,
                RDATA: {
                    key_tag: 0,
                    labels: 2,
                    algorithm: 13,
                    original_ttl: 10,
                    type_covered: RecordType.A,
                    signer: ['example', 'com', ''],
                    sig_expiration: Math.floor(Date.now() / 1000) + 10,
                    sig_inception: Math.floor(Date.now() / 1000) - 10,
                } as RDATA[RecordType.RRSIG],
            } as ResponseRecord<RecordType.RRSIG>;
            CNAMERRSIG = {
                NAME: ['example', 'com', ''],
                TYPE: RecordType.RRSIG,
                CLASS: CLASS.IN,
                TTL: 10,
                RDATA: {
                    key_tag: 0,
                    labels: 2,
                    algorithm: 13,
                    original_ttl: 10,
                    type_covered: RecordType.CNAME,
                    signer: ['example', 'com', ''],
                    sig_expiration: Math.floor(Date.now() / 1000) + 10,
                    sig_inception: Math.floor(Date.now() / 1000) - 10,
                } as RDATA[RecordType.RRSIG],
            } as ResponseRecord<RecordType.RRSIG>;
            TXTRRSIG = {
                NAME: ['example', 'com', ''],
                TYPE: RecordType.RRSIG,
                CLASS: CLASS.IN,
                TTL: 10,
                RDATA: {
                    key_tag: 0,
                    labels: 2,
                    algorithm: 13,
                    original_ttl: 10,
                    type_covered: RecordType.TXT,
                    signer: ['example', 'com', ''],
                    sig_expiration: Math.floor(Date.now() / 1000) + 10,
                    sig_inception: Math.floor(Date.now() / 1000) - 10,
                } as RDATA[RecordType.RRSIG],
            } as ResponseRecord<RecordType.RRSIG>;
            DNSKEYRRSIG = {
                NAME: ['example', 'com', ''],
                TYPE: RecordType.RRSIG,
                CLASS: CLASS.IN,
                TTL: 10,
                RDATA: {
                    key_tag: 0,
                    labels: 2,
                    algorithm: 13,
                    original_ttl: 10,
                    type_covered: RecordType.DNSKEY,
                    signer: ['example', 'com', ''],
                    sig_expiration: Math.floor(Date.now() / 1000) + 10,
                    sig_inception: Math.floor(Date.now() / 1000) - 10,
                } as RDATA[RecordType.RRSIG],
            } as ResponseRecord<RecordType.RRSIG>;
            ARRSIG.RDATA.signature = await crypto.subtle.sign(ALGORITHMS[13], resolver.keys['example.com'].privateKey, signedData(ARRSIG.RDATA, [ARecord]));
            CNAMERRSIG.RDATA.signature = await crypto.subtle.sign(ALGORITHMS[13], resolver.keys['example.com'].privateKey, signedData(CNAMERRSIG.RDATA, [CNAMERecord]));
            TXTRRSIG.RDATA.signature = await crypto.subtle.sign(ALGORITHMS[13], resolver.keys['example.com'].privateKey, signedData(TXTRRSIG.RDATA, [TXTRecord]));
            DNSKEYRRSIG.RDATA.signature = await crypto.subtle.sign(ALGORITHMS[13], resolver.keys['example.com'].privateKey, signedData(DNSKEYRRSIG.RDATA, [DNSKEYRecord]));
        })
        it('should handle empty RRSet', () => {
            return expect(validateRecords([], resolver)).to.eventually.rejectedWith('Unable to validate');
        })
        it('should handle a variety of record types', () => {
            return expect(validateRecords([ARecord, CNAMERecord, TXTRecord, DNSKEYRecord, ARRSIG, CNAMERRSIG, TXTRRSIG, DNSKEYRRSIG, ZONEKEY], resolver)).to.eventually.be.true;
        })
        it('should reject when a RRSig exists for a type covered but there are no records in the RRSet of that type', () => {
            return expect(validateRecords([CNAMERecord, TXTRecord, DNSKEYRecord, ARRSIG, CNAMERRSIG, TXTRRSIG, DNSKEYRRSIG, ZONEKEY], resolver)).to.eventually.be.true;
        })
        xit('should reject when records are present in the RRSet that are not signed by an RRSIG', () => {
            return expect(validateRecords([ARecord, CNAMERecord, TXTRecord, DNSKEYRecord, ARRSIG, CNAMERRSIG, TXTRRSIG, DNSKEYRRSIG, ZONEKEY], resolver)).to.eventually.be.rejected;
        })
        xit('should reject an incomplete RRSet type for what was signed by a single RRSIG', () => {
            return expect(validateRecords([ARecord, CNAMERecord, TXTRecord, DNSKEYRecord, ARRSIG, CNAMERRSIG, TXTRRSIG, DNSKEYRRSIG, ZONEKEY], resolver)).to.eventually.be.rejected;
        })
        xit('should handle a mix of DNSKEY zone keys and non-zone keys', async () => {
        })
        xit('should correctly match the RRSIG to the RRSubset', async () => {
        })
        xit('should correctly handle combinations of a.foo.bar and afoo.bar for RRSIG signer', async () => {
        })
        xit('should correctly reject invalid records', async () => {
        })
        xit('should correctly reject expired RRSIG', async () => {
        })
    })
// TODO https://github.com/jhnns/rewire

// TODO https://dnssec.works/  https://dnssec-works.translate.goog/?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp

// TODO create A *.example.i2labs.ca and resolve wildcard.example.i2labs.ca ; this can mess with the label count when validating
    describe('validator', () => {
        it('should ')
    })
})