// The SDK's fetch and XHR interceptors around a response cut by a BLOCK (docs/showcase/응답차단-수정계획.md RT-8,
// R-6 to R-10). Runs on Node 22 with its own fetch Response, ReadableStream and AbortController; XMLHttpRequest is a
// test double with the browser's constants. Run: node --test contexa-identity/src/test/js
// CONTEXA_MFA_SDK=<path> runs it on another copy of the SDK.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const SDK = process.env.CONTEXA_MFA_SDK
    ?? fileURLToPath(new URL('../../main/resources/static/js/contexa-mfa-sdk.js', import.meta.url));
const SOURCE = readFileSync(SDK, 'utf8');
const MARKER = '\n__CONTEXA_RESPONSE_BLOCKED__:BLOCK\n';
const encoder = new TextEncoder();

function storage() {
    const values = new Map();
    return {
        getItem: (key) => (values.has(key) ? values.get(key) : null),
        setItem: (key, value) => values.set(key, String(value)),
        removeItem: (key) => values.delete(key),
        clear: () => values.clear(),
        key: (index) => [...values.keys()][index] ?? null,
        get length() {
            return values.size;
        },
    };
}

/** A browser XMLHttpRequest stand-in: the readyState constants and the events the interceptor listens to. */
class FakeXHR extends EventTarget {
    static UNSENT = 0;
    static OPENED = 1;
    static HEADERS_RECEIVED = 2;
    static LOADING = 3;
    static DONE = 4;
    static last = null;

    constructor() {
        super();
        this.readyState = 0;
        this.status = 0;
        this.responseType = '';
        this.aborted = false;
        this.text = '';
        this.responseHeaders = {};
        FakeXHR.last = this;
    }

    open(method, url) {
        this.readyState = 1;
        this.url = url;
    }

    send() {
    }

    abort() {
        this.aborted = true;
    }

    getResponseHeader(name) {
        return this.responseHeaders[name.toLowerCase()] ?? null;
    }

    get responseText() {
        if (this.responseType !== '' && this.responseType !== 'text') {
            throw new DOMException('responseText is only available for text', 'InvalidStateError');
        }
        return this.text;
    }

    receiveHeaders(headers, status = 200) {
        this.responseHeaders = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
        this.status = status;
        this.readyState = 2;
        this.dispatchEvent(new Event('readystatechange'));
    }

    receive(text) {
        this.text += text;
        this.readyState = 3;
        this.dispatchEvent(new Event('readystatechange'));
    }

    fail() {
        this.readyState = 4;
        this.dispatchEvent(new Event('readystatechange'));
        this.dispatchEvent(new Event('error'));
    }
}

/** Loads the SDK into a fresh page. {@code fetchImpl} answers its fetches. */
function page({ fetchImpl, config, pathname = '/orders/12' } = {}) {
    const navigated = [];
    const location = {
        origin: 'http://app.test',
        pathname,
        search: '',
        hash: '',
        get href() {
            return 'http://app.test' + pathname;
        },
        set href(value) {
            navigated.push(value);
        },
        assign(value) {
            navigated.push(value);
        },
        replace(value) {
            navigated.push(value);
        },
    };
    const quiet = { log() {}, info() {}, warn() {}, error() {}, debug() {} };
    const window = {
        location,
        sessionStorage: storage(),
        localStorage: storage(),
        navigator: { language: 'en', credentials: {} },
        document: { querySelector: () => null, querySelectorAll: () => [], documentElement: { lang: 'en' }, cookie: '' },
        console: quiet,
        fetch: fetchImpl ?? (() => Promise.reject(new Error('no fetch in this test'))),
        XMLHttpRequest: FakeXHR,
        Response, ReadableStream, Headers, Request, TextDecoder, TextEncoder, URL, URLSearchParams,
        AbortController, DOMException, Event, EventTarget, Uint8Array, setTimeout, clearTimeout, queueMicrotask,
    };
    if (config) {
        window.__MFA_CONFIG__ = config;
    }
    window.window = window;
    vm.runInContext(SOURCE, vm.createContext(window), { filename: 'contexa-mfa-sdk.js' });
    return { window, navigated };
}

/** A response whose body sends the chunks one by one, then closes, fails or waits for the abort. */
function streamed({ status = 200, monitored = true, chunks = [], end = 'close', signal, url, redirected }) {
    const body = new ReadableStream({
        async start(controller) {
            for (const chunk of chunks) {
                await new Promise((resolve) => setTimeout(resolve, 2));
                controller.enqueue(encoder.encode(chunk));
            }
            if (end === 'close') {
                controller.close();
            } else if (end === 'error') {
                controller.error(new TypeError('network error'));
            } else if (end === 'abort') {
                signal.addEventListener('abort', () => controller.error(new DOMException('aborted', 'AbortError')));
            }
        },
    });
    const headers = { 'Content-Type': 'application/x-ndjson' };
    if (monitored) {
        headers['X-Contexa-Monitored'] = 'true';
        headers['X-Contexa-Blocked-Redirect'] = '/contexa/zero-trust/blocked';
    }
    const response = new Response(body, { status, headers });
    if (url) {
        Object.defineProperty(response, 'url', { value: url });
    }
    if (redirected) {
        Object.defineProperty(response, 'redirected', { value: true });
    }
    return response;
}

/** Reads the body as the application would: the text received and how it ended. */
async function readAll(response) {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let text = '';
    try {
        for (;;) {
            const { done, value } = await reader.read();
            if (done) {
                return { text, error: null };
            }
            text += decoder.decode(value, { stream: true });
        }
    } catch (error) {
        return { text, error };
    }
}

const tick = (ms = 20) => new Promise((resolve) => setTimeout(resolve, ms));

test('a marker split across two chunks is found, and none of it reaches the application', async () => {
    const { window, navigated } = page({
        fetchImpl: () => Promise.resolve(streamed({
            chunks: ['{"row":1}\n{"row":2}\n', '\n__CONTEXA_RESP', 'ONSE_BLOCKED__:BLOCK\n'], end: 'error',
        })),
    });

    const read = await readAll(await window.fetch('/api/exports/stream'));

    assert.equal(read.text, '{"row":1}\n{"row":2}\n');
    assert.match(String(read.error), /Response blocked/);
    assert.equal(JSON.stringify(navigated), JSON.stringify(['/']));
});

test('the rows before the marker in the same chunk reach the application', async () => {
    const { window, navigated } = page({
        fetchImpl: () => Promise.resolve(streamed({ chunks: ['{"row":1}\n{"row":2}' + MARKER], end: 'error' })),
    });

    const read = await readAll(await window.fetch('/api/exports/stream'));

    assert.equal(read.text, '{"row":1}\n{"row":2}');
    assert.equal(navigated.length, 1);
});

test('a stream the application aborts reaches it as its abort, and the page stays', async () => {
    const controller = new AbortController();
    const { window, navigated } = page({
        fetchImpl: (input, init) => Promise.resolve(streamed({
            chunks: ['{"row":1}\n'], end: 'abort', signal: init.signal,
        })),
    });

    const response = await window.fetch('/api/search?q=a', { signal: controller.signal });
    const reading = readAll(response);
    await tick();
    controller.abort();
    const read = await reading;

    assert.equal(read.text, '{"row":1}\n');
    assert.equal(read.error?.name, 'AbortError');
    assert.equal(navigated.length, 0);
});

test('a network failure without the marker reaches the application as it is, and the page stays', async () => {
    const { window, navigated } = page({
        fetchImpl: () => Promise.resolve(streamed({ chunks: ['{"row":1}\n'], end: 'error' })),
    });

    const read = await readAll(await window.fetch('/api/exports/stream'));

    assert.equal(read.text, '{"row":1}\n');
    assert.ok(read.error instanceof TypeError, String(read.error));
    assert.equal(navigated.length, 0);
});

test('a monitored 403 that carries the marker is the cut before the commit: the page moves on', async () => {
    const { window, navigated } = page({
        fetchImpl: () => Promise.resolve(streamed({ status: 403, chunks: [MARKER], end: 'close' })),
    });

    const answered = await Promise.race([window.fetch('/api/exports/stream').then(() => 'answered'), tick(100)]);

    assert.equal(answered, undefined, 'the application does not get the cut response');
    assert.equal(JSON.stringify(navigated), JSON.stringify(['/']));
});

test('a monitored 403 without the marker is left to the application', async () => {
    const { window, navigated } = page({
        fetchImpl: () => Promise.resolve(streamed({ status: 403, chunks: ['{"error":"FORBIDDEN"}'], end: 'close' })),
    });

    const response = await window.fetch('/api/exports/stream');

    assert.equal(response.status, 403);
    assert.equal(await response.text(), '{"error":"FORBIDDEN"}');
    assert.equal(navigated.length, 0);
});

test('a monitored response keeps its url, redirected and status', async () => {
    const { window } = page({
        fetchImpl: () => Promise.resolve(streamed({
            chunks: ['{"row":1}\n'], url: 'http://app.test/api/exports/stream', redirected: true,
        })),
    });

    const response = await window.fetch('/api/exports/stream');

    assert.equal(response.url, 'http://app.test/api/exports/stream');
    assert.equal(response.redirected, true);
    assert.equal(response.status, 200);
    assert.equal((await readAll(response)).text, '{"row":1}\n');
});

test('fetch and XHR move to the same place after a cut: the configured prefix, or the root', async () => {
    for (const [config, expected] of [[undefined, '/'], [{ urlPrefix: '/app' }, '/app/']]) {
        const viaFetch = page({
            config, fetchImpl: () => Promise.resolve(streamed({ chunks: [MARKER], end: 'error' })),
        });
        await readAll(await viaFetch.window.fetch('/api/exports/stream'));

        const viaXhr = page({ config });
        const xhr = new viaXhr.window.XMLHttpRequest();
        xhr.open('GET', '/api/exports/stream');
        xhr.send();
        FakeXHR.last.receiveHeaders({ 'X-Contexa-Monitored': 'true' });
        FakeXHR.last.receive('{"row":1}' + MARKER);

        assert.equal(JSON.stringify(viaFetch.navigated), JSON.stringify([expected]), 'fetch, prefix ' + config?.urlPrefix);
        assert.equal(JSON.stringify(viaXhr.navigated), JSON.stringify([expected]), 'XHR, prefix ' + config?.urlPrefix);
    }
});

test('XMLHttpRequest keeps its readyState constants and its instances', () => {
    const { window } = page();

    assert.equal(window.XMLHttpRequest.UNSENT, 0);
    assert.equal(window.XMLHttpRequest.OPENED, 1);
    assert.equal(window.XMLHttpRequest.HEADERS_RECEIVED, 2);
    assert.equal(window.XMLHttpRequest.LOADING, 3);
    assert.equal(window.XMLHttpRequest.DONE, 4);
    const xhr = new window.XMLHttpRequest();
    assert.ok(xhr instanceof window.XMLHttpRequest);
    assert.ok(xhr instanceof FakeXHR);
});

test('XHR finds a marker split across two progress events once, aborts and moves on', () => {
    const { window, navigated } = page();
    const xhr = new window.XMLHttpRequest();
    xhr.open('GET', '/api/exports/stream');
    xhr.send();
    const raw = FakeXHR.last;
    raw.receiveHeaders({ 'X-Contexa-Monitored': 'true' });

    raw.receive('{"row":1}\n'.repeat(2000) + '\n__CONTEXA_RESP');
    assert.equal(navigated.length, 0);
    raw.receive('ONSE_BLOCKED__:BLOCK\n');
    raw.receive('');

    assert.equal(JSON.stringify(navigated), JSON.stringify(['/']));
    assert.equal(raw.aborted, true);
});

test('an XHR network failure without the marker stays with the application', () => {
    const { window, navigated } = page();
    const xhr = new window.XMLHttpRequest();
    let failed = 0;
    xhr.addEventListener('error', () => {
        failed++;
    });
    xhr.open('GET', '/api/exports/stream');
    xhr.send();
    const raw = FakeXHR.last;
    raw.receiveHeaders({ 'X-Contexa-Monitored': 'true', 'X-Contexa-Blocked-Redirect': '/contexa/zero-trust/blocked' });
    raw.receive('{"row":1}\n');

    raw.fail();

    assert.equal(failed, 1);
    assert.equal(navigated.length, 0);
});

test('an XHR whose response is not text is not read for the marker', () => {
    const { window, navigated } = page();
    const xhr = new window.XMLHttpRequest();
    xhr.responseType = 'blob';
    xhr.open('GET', '/api/exports/file');
    xhr.send();
    const raw = FakeXHR.last;
    raw.responseType = 'blob';

    raw.receiveHeaders({ 'X-Contexa-Monitored': 'true' });
    raw.receive('binary');

    assert.equal(navigated.length, 0);
});
