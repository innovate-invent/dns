import {expect} from 'chai';

export function cmp(expected: any[], result: any[], keys: string[]): void {
    if (keys) {
        expect(result).to.have.lengthOf(expected.length)
        for (let i = 0; i < expected.length; ++i) {
            for (const key of keys) {
                expect(result[i][key]).to.be.eql(expected[i][key]);
            }
        }
    } else {
        expect(expected).to.be.eql(result);
    }
}

const originalFetch = window.fetch.bind(window);
let fetchResponse = originalFetch;
window.fetch = async (input: RequestInfo | URL, init?: RequestInit)=>{
    return fetchResponse(input, init);
};

export function setFetch(fn: (input: RequestInfo | URL, init?: RequestInit)=>Promise<Response>) {
    fetchResponse = fn;
}

export function restoreFetch() {
    fetchResponse = originalFetch;
}