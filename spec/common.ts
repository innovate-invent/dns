const expect = chai.expect;

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
