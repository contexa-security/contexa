import { localLink } from './http.js';

export class ObservationStream {
    constructor(path, origin, changed, status) {
        this.url = localLink(path, origin);
        this.changed = changed;
        this.status = status;
        this.cursor = '0';
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) this.close();
            else this.open();
        });
        window.addEventListener('pagehide', () => this.close());
        window.addEventListener('pageshow', () => this.open());
    }

    open() {
        if (this.stopped || this.source || document.hidden) return;
        const url = new URL(this.url);
        url.searchParams.set('after', this.cursor);
        this.source = new EventSource(url, { withCredentials: true });
        this.status('connecting');
        this.source.addEventListener('connected', () => {
            this.status('connected');
            this.changed();
        });
        this.source.addEventListener('observation', event => {
            if (!/^[0-9]+$/.test(event.lastEventId)) return;
            if (BigInt(event.lastEventId) <= BigInt(this.cursor)) return;
            this.cursor = event.lastEventId;
            this.changed();
        });
        this.source.addEventListener('refresh', () => this.changed());
        this.source.onerror = () => this.status('reconnecting');
    }

    close() {
        this.source?.close();
        this.source = null;
        this.status('paused');
    }

    stop() {
        this.stopped = true;
        this.close();
    }
}
