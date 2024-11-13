import {DNSError} from "../src/dns";
import FetchContext from "../src/FetchContext";

const expect = chai.expect;

describe('Basecontext', ()=>{
    describe('_fetch', () => {
        it('should not time out', async () => {
            const context = new FetchContext(5000, 1);
            await context.fetch("https://httpstat.us/200?sleep=4500");
        }).timeout(6000)
        it('should time out', async () => {
            const context = new FetchContext(0, 1);
            try {
                await context.fetch("https://httpstat.us/200?sleep=5000");
                expect.fail();
            } catch (e) {
                expect(e).is.eql(DNSError.TIMEOUT);
            }
        })
        it('should abort', async () => {
            const context = new FetchContext(3, 500);
            const p = context.fetch("https://httpstat.us/200?sleep=5000")
            try {
                context.cancel();
                await p;
                expect.fail("did not abort")
            } catch (e) {
                expect(e).to.eql(DNSError.CANCELLED);
            }
        }).timeout(5000)
    })
})