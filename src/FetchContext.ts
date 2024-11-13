import {DNSError} from "./dns";

export default class FetchContext {
    private readonly _timeout: number;
    private readonly _tries: number;
    private _pending: Set<AbortController> = new Set();

    constructor(timeout: number = -1, tries: number = 4) {
        this._timeout = timeout;
        this._tries = tries;
    }

    /**
     * Fetch with abort, timeout, and retry
     * @param resource URL of resource to fetch
     * @param options RequestInit options to forward to fetch
     * @protected
     */
    public async fetch(resource: string, options?: RequestInit): Promise<Response> {
        const controller = new AbortController();
        let id;
        this._pending.add(controller);

        try {
            for (let _try = this._tries; _try > 0; --_try) {
                let timeout = false;
                if (this._timeout !== -1) id = setTimeout(() => {
                    timeout = true;
                    controller.abort();
                }, this._timeout);
                try {
                    return await fetch(resource, {
                        ...options,
                        signal: controller.signal
                    });
                } catch (e) {
                    if (e.name === 'AbortError') {
                        if (timeout) throw DNSError.TIMEOUT;
                        throw DNSError.CANCELLED;
                    }
                    if (_try > 0) continue;
                    // TODO translate e to DNSErrors
                    switch (e.name) {
                        case '':

                    }
                    throw e;
                } finally {
                    if (id) clearTimeout(id);
                }
            }
        } finally {
            this._pending.delete(controller);
        }
    }

    public cancel(): void {
        for (const controller of this._pending) controller.abort();
        this._pending.clear();
    }
}