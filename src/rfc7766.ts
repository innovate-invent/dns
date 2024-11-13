/**
 * RFC7766 DNS over TCP Resolver
 * https://tools.ietf.org/html/rfc7766
 */

import {createConnection, Socket} from "node:net";

import {parseResponse, DNSResponse as DNSResponse, WireFormatResolver} from "./rfc1035.js";
import {DNSError} from "./dns";

export default class Resolver extends WireFormatResolver {
    protected servers: string[] = ['1.1.1.1:53', '208.67.222.222:53', '208.67.220.220:53', '94.140.14.140:53', '94.140.14.141:53', '8.8.8.8:53', '8.8.4.4:53', '9.9.9.9:53'];

    private _pending: Set<Socket> = new Set();

    async _submit(server: string, request: ArrayBuffer, keepRDATA: boolean = false): Promise<[DNSResponse, ArrayBuffer]> {
        const [host, port] = server.split(':');
        let response: ArrayBuffer;
        for (let _try = this._tries; _try > 0; --_try) {
            try {
                response = await new Promise<ArrayBuffer>((resolve, reject) => {
                    const chunks: Buffer[] = [];
                    const conn = createConnection(parseInt(port, 10), host);
                    this._pending.add(conn);
                    conn.on('ready', () => {
                        conn.end(new Uint8Array(request));
                    }).on('data', data => {
                        chunks.push(data);
                    }).on('end', () => {
                        const totalSize = chunks.reduce((acc, cur) => acc + cur.byteLength, 0);
                        const data = new Uint8Array(totalSize);
                        let offset = 0;
                        chunks.forEach(chunk => {
                            data.set(chunk, offset);
                            offset += chunk.byteLength;
                        });
                        resolve(data.buffer);
                    }).on('error', error => {
                        this._pending.delete(conn);
                        reject(error);
                    }).on('timeout', () => {
                        this._pending.delete(conn);
                        reject(DNSError.TIMEOUT);
                    }).setTimeout(this._timeout);
                });
                break;
            } catch (e) {
                if (e !== DNSError.TIMEOUT) throw e;
            }
        }

        return [parseResponse(response, keepRDATA), response];
    }

    cancel() {
        this._pending.forEach(soc => soc.resetAndDestroy());
        this._pending.clear();
    }
}
