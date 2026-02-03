/**
 * Contexa Streaming Library - Bundle
 *
 * A reusable streaming library for LLM responses with customizable UI adapters.
 * This bundle includes all components in a single file.
 *
 * @version 1.0.0
 * @license MIT
 *
 * @example Basic usage
 * const client = new ContexaStreaming.StreamingClientBuilder()
 *     .withModalUI()
 *     .build();
 *
 * await client.streamWithAdapter('/api/llm/stream', { query: 'Hello' });
 */
(function(global) {
    'use strict';

    // ============================================================
    // UIAdapter - Base Class for Streaming UI Adapters
    // ============================================================
    class UIAdapter {
        constructor(options = {}) {
            this.options = options;
        }

        onStreamStart(query) {}
        onChunk(chunk) {}
        onSentence(sentence) {}
        onFinalResponse(response) {}
        onError(error) {
            console.error('Streaming error:', error);
        }
        onRetry(attempt, maxAttempts) {}
        onComplete() {}
        onAbort() {}
        destroy() {}
    }

    // ============================================================
    // StreamingClient - Universal LLM Streaming Client
    // ============================================================
    class StreamingClient {
        static DEFAULT_CONFIG = {
            markers: {
                FINAL_RESPONSE: '###FINAL_RESPONSE###',
                DONE: '[DONE]',
                ERROR_PREFIX: 'ERROR:',
                JSON_START: '===JSON_START===',
                JSON_END: '===JSON_END==='
            },
            streaming: {
                maxRetries: 3,
                retryDelay: 1000,
                retryMultiplier: 1.5,
                timeoutMs: 30000
            }
        };

        constructor(config = {}) {
            this.config = this.mergeConfig(StreamingClient.DEFAULT_CONFIG, config);
            this.abortController = null;
            this.isAborted = false;
            this.retryCount = 0;
        }

        mergeConfig(defaults, overrides) {
            const result = { ...defaults };
            for (const key in overrides) {
                if (overrides[key] !== undefined && overrides[key] !== null) {
                    if (typeof overrides[key] === 'object' && !Array.isArray(overrides[key])) {
                        result[key] = this.mergeConfig(defaults[key] || {}, overrides[key]);
                    } else {
                        result[key] = overrides[key];
                    }
                }
            }
            return result;
        }

        async stream(url, requestData, callbacks = {}) {
            return new Promise((resolve, reject) => {
                let finalResponse = null;

                this.startStreaming(url, requestData, {
                    onChunk: (chunk) => {
                        if (callbacks.onChunk) callbacks.onChunk(chunk);
                    },
                    onFinalResponse: (data) => {
                        finalResponse = this.parseFinalResponse(data);
                        if (callbacks.onFinalResponse) callbacks.onFinalResponse(finalResponse);
                    },
                    onComplete: () => {
                        if (callbacks.onComplete) callbacks.onComplete();
                        resolve(finalResponse);
                    },
                    onError: (error) => {
                        if (callbacks.onError) callbacks.onError(error);
                        reject(error);
                    },
                    onRetry: (attempt, max) => {
                        if (callbacks.onRetry) callbacks.onRetry(attempt, max);
                    },
                    onAbort: () => {
                        if (callbacks.onAbort) callbacks.onAbort();
                        resolve(null);
                    },
                    onDone: callbacks.onDone,
                    onEvent: callbacks.onEvent,
                    onStreamError: callbacks.onStreamError
                });
            });
        }

        async startStreaming(url, requestData, callbacks) {
            this.isAborted = false;
            this.abortController = new AbortController();

            const timeoutMs = this.config.streaming.timeoutMs || 30000;
            const timeoutId = setTimeout(() => {
                if (!this.isAborted) {
                    this.abortController.abort();
                    if (callbacks.onError) {
                        callbacks.onError(new Error(`Request timeout after ${timeoutMs}ms`));
                    }
                }
            }, timeoutMs);

            try {
                const response = await fetch(url, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'text/event-stream',
                        ...this.getCsrfHeaders()
                    },
                    body: JSON.stringify(requestData),
                    signal: this.abortController.signal
                });

                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }

                this.retryCount = 0;
                await this.processStream(response, callbacks);
                clearTimeout(timeoutId);

            } catch (error) {
                clearTimeout(timeoutId);
                if (error.name === 'AbortError' || this.isAborted) {
                    if (callbacks.onAbort) callbacks.onAbort();
                    return;
                }

                const streamingConfig = this.config.streaming;
                if (this.retryCount < streamingConfig.maxRetries) {
                    this.retryCount++;
                    const delay = streamingConfig.retryDelay *
                        Math.pow(streamingConfig.retryMultiplier, this.retryCount - 1);

                    if (callbacks.onRetry) callbacks.onRetry(this.retryCount, streamingConfig.maxRetries);
                    await this.sleep(delay);

                    if (!this.isAborted) {
                        return this.startStreaming(url, requestData, callbacks);
                    }
                }

                if (callbacks.onError) callbacks.onError(error);
            }
        }

        async processStream(response, callbacks) {
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';

            try {
                while (true) {
                    const { done, value } = await reader.read();

                    if (done) {
                        if (buffer.trim()) this.processSSEData(buffer, callbacks);
                        break;
                    }

                    const text = decoder.decode(value, { stream: true });
                    buffer += text;

                    const lines = buffer.split('\n');
                    buffer = lines.pop() || '';

                    for (const line of lines) {
                        this.processSSELine(line, callbacks);
                    }
                }

                if (callbacks.onComplete) callbacks.onComplete();
            } finally {
                reader.releaseLock();
            }
        }

        processSSELine(line, callbacks) {
            const trimmedLine = line.trim();
            if (!trimmedLine || trimmedLine.startsWith(':')) return;

            if (trimmedLine.startsWith('data:')) {
                const data = trimmedLine.substring(5).trim();
                this.processSSEData(data, callbacks);
            } else if (trimmedLine.startsWith('event:')) {
                const event = trimmedLine.substring(6).trim();
                if (callbacks.onEvent) callbacks.onEvent(event);
            }
        }

        processSSEData(data, callbacks) {
            if (!data) return;

            const markers = this.config.markers;

            if (data === markers.DONE) {
                if (callbacks.onDone) callbacks.onDone();
                return;
            }

            if (data.startsWith(markers.ERROR_PREFIX)) {
                const errorMessage = data.substring(markers.ERROR_PREFIX.length).trim();
                if (callbacks.onStreamError) callbacks.onStreamError(errorMessage);
                return;
            }

            if (data.includes(markers.FINAL_RESPONSE)) {
                if (callbacks.onFinalResponse) callbacks.onFinalResponse(data);
                return;
            }

            if (callbacks.onChunk) callbacks.onChunk(data);
        }

        parseFinalResponse(data) {
            if (!data) return null;

            try {
                const markers = this.config.markers;
                if (data.includes(markers.FINAL_RESPONSE)) {
                    const markerIndex = data.indexOf(markers.FINAL_RESPONSE);
                    const jsonString = data.substring(markerIndex + markers.FINAL_RESPONSE.length);
                    return this.parseJson(jsonString);
                }
                return this.parseJson(data);
            } catch (error) {
                console.error('Failed to parse final response:', error);
                return { parseError: true, raw: data, errorMessage: error.message };
            }
        }

        parseJson(jsonString) {
            if (!jsonString || typeof jsonString !== 'string') throw new Error('Invalid JSON input');
            const trimmed = jsonString.trim();
            if (!trimmed) throw new Error('Empty JSON input');
            return JSON.parse(trimmed);
        }

        getCsrfHeaders() {
            if (typeof document === 'undefined') return {};
            const csrfToken = document.querySelector('meta[name="_csrf"]')?.content;
            const csrfHeader = document.querySelector('meta[name="_csrf_header"]')?.content;
            return (csrfToken && csrfHeader) ? { [csrfHeader]: csrfToken } : {};
        }

        abort() {
            this.isAborted = true;
            if (this.abortController) {
                this.abortController.abort();
                this.abortController = null;
            }
        }

        reset() {
            this.abort();
            this.retryCount = 0;
            this.isAborted = false;
        }

        isStreaming() {
            return this.abortController !== null && !this.isAborted;
        }

        sleep(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        }

        getConfig() {
            return this.config;
        }
    }

    // ============================================================
    // ConsoleAdapter - Console Output Adapter
    // ============================================================
    class ConsoleAdapter extends UIAdapter {
        constructor(options = {}) {
            super(options);
            this.prefix = options.prefix || '[STREAM]';
            this.showTimestamp = options.showTimestamp || false;
        }

        formatMessage(type, message) {
            const timestamp = this.showTimestamp ? `[${new Date().toISOString()}] ` : '';
            return `${timestamp}${this.prefix} ${type}: ${message}`;
        }

        onStreamStart(query) { console.log(this.formatMessage('START', query)); }
        onChunk(chunk) { console.log(this.formatMessage('CHUNK', chunk)); }
        onSentence(sentence) { console.log(this.formatMessage('SENTENCE', sentence)); }
        onFinalResponse(response) { console.log(this.formatMessage('FINAL', JSON.stringify(response, null, 2))); }
        onError(error) { console.error(this.formatMessage('ERROR', error.message || error)); }
        onRetry(attempt, maxAttempts) { console.warn(this.formatMessage('RETRY', `Attempt ${attempt}/${maxAttempts}`)); }
        onComplete() { console.log(this.formatMessage('COMPLETE', 'Streaming finished')); }
        onAbort() { console.log(this.formatMessage('ABORT', 'Streaming aborted')); }
    }

    // ============================================================
    // SimpleProgressAdapter - Simple Progress UI Adapter
    // ============================================================
    class SimpleProgressAdapter extends UIAdapter {
        constructor(options = {}) {
            super(options);
            this.container = options.container || document.body;
            this.loadingMessage = options.loadingMessage || 'Processing...';
            this.errorMessage = options.errorMessage || 'An error occurred';
            this.retryMessage = options.retryMessage || 'Retrying...';
            this.className = options.className || 'streaming-progress';
            this.progressElement = null;
        }

        createProgressHTML(query) {
            return `
                <div class="${this.className}">
                    <div class="${this.className}-spinner"></div>
                    <div class="${this.className}-text">${this.escapeHtml(this.loadingMessage)}</div>
                    <div class="${this.className}-query">${this.escapeHtml(query.substring(0, 50))}${query.length > 50 ? '...' : ''}</div>
                </div>
            `;
        }

        createDefaultStyles() {
            return `
                .${this.className} { position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); padding: 20px 30px; background: rgba(0, 0, 0, 0.8); color: white; border-radius: 8px; text-align: center; z-index: 10000; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
                .${this.className}-spinner { width: 30px; height: 30px; border: 3px solid rgba(255, 255, 255, 0.3); border-top-color: white; border-radius: 50%; margin: 0 auto 10px; animation: ${this.className}-spin 1s linear infinite; }
                .${this.className}-text { font-size: 14px; margin-bottom: 5px; }
                .${this.className}-query { font-size: 12px; opacity: 0.7; }
                .${this.className}-error { color: #ff6b6b; }
                .${this.className}-retry { color: #ffd93d; }
                @keyframes ${this.className}-spin { to { transform: rotate(360deg); } }
            `;
        }

        injectStyles() {
            const styleId = `${this.className}-styles`;
            if (!document.getElementById(styleId)) {
                const style = document.createElement('style');
                style.id = styleId;
                style.textContent = this.createDefaultStyles();
                document.head.appendChild(style);
            }
        }

        escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        onStreamStart(query) {
            this.destroy();
            this.injectStyles();
            const wrapper = document.createElement('div');
            wrapper.innerHTML = this.createProgressHTML(query);
            this.progressElement = wrapper.firstElementChild;
            this.container.appendChild(this.progressElement);
        }

        onChunk(chunk) {
            const textEl = this.progressElement?.querySelector(`.${this.className}-text`);
            if (textEl) {
                const displayText = chunk.substring(0, 50) + (chunk.length > 50 ? '...' : '');
                textEl.textContent = displayText;
            }
        }

        onError(error) {
            const textEl = this.progressElement?.querySelector(`.${this.className}-text`);
            if (textEl) {
                textEl.textContent = this.errorMessage;
                textEl.classList.add(`${this.className}-error`);
            }
        }

        onRetry(attempt, maxAttempts) {
            const textEl = this.progressElement?.querySelector(`.${this.className}-text`);
            if (textEl) {
                textEl.textContent = `${this.retryMessage} (${attempt}/${maxAttempts})`;
                textEl.classList.add(`${this.className}-retry`);
            }
        }

        onComplete() { this.destroy(); }
        onAbort() { this.destroy(); }

        destroy() {
            if (this.progressElement && this.progressElement.parentNode) {
                this.progressElement.parentNode.removeChild(this.progressElement);
                this.progressElement = null;
            }
        }
    }

    // ============================================================
    // ModalUIAdapter - Modal-based Streaming UI Adapter
    // ============================================================
    class ModalUIAdapter extends UIAdapter {
        constructor(options = {}) {
            super(options);
            this.modalId = options.modalId || 'streaming-modal';
            this.headerText = options.headerText || 'AI Analyzing...';
            this.hideDelay = options.hideDelay || 300;
            this.animationDelay = options.animationDelay || 100;
            this.currentModal = null;
        }

        onStreamStart(query) {
            this.hide();
            this.injectStyles();
            const modalHtml = this.createModalHtml(query);
            document.body.insertAdjacentHTML('beforeend', modalHtml);
            this.currentModal = document.getElementById(this.modalId);
            requestAnimationFrame(() => {
                if (this.currentModal) this.currentModal.classList.add('show');
            });
        }

        onChunk(chunk) { this.addStep(chunk); }
        onSentence(sentence) { this.addStep(sentence); }

        onFinalResponse(response) { this.updateHeader('Complete'); }

        onError(error) {
            this.updateHeader('Error');
            this.addStep(`Error: ${error.message || error}`);
            const content = this.currentModal?.querySelector('#streaming-content');
            if (content) content.classList.add('error-state');
        }

        onRetry(attempt, maxAttempts) {
            this.updateHeader(`Retrying... (${attempt}/${maxAttempts})`);
            this.addStep(`Connection lost. Retrying... (${attempt}/${maxAttempts})`);
        }

        onComplete() {
            setTimeout(() => { this.hide(); }, this.hideDelay);
        }

        onAbort() { this.hide(); }

        hide() {
            if (this.currentModal) {
                this.currentModal.classList.remove('show');
                this.currentModal.style.display = 'none';
                const modal = this.currentModal;
                this.currentModal = null;
                setTimeout(() => {
                    if (modal && modal.parentNode) modal.parentNode.removeChild(modal);
                }, this.hideDelay);
            }
            const existingModal = document.getElementById(this.modalId);
            if (existingModal && existingModal.parentNode) {
                existingModal.parentNode.removeChild(existingModal);
            }
        }

        addStep(message) {
            const content = this.currentModal?.querySelector('#streaming-content');
            if (!content) return;
            const step = document.createElement('div');
            step.className = 'streaming-step';
            step.textContent = message;
            content.appendChild(step);
            requestAnimationFrame(() => {
                step.classList.add('visible');
                content.scrollTop = content.scrollHeight;
            });
        }

        updateHeader(text) {
            const header = this.currentModal?.querySelector('.ctx-header-text');
            if (header) header.textContent = text;
        }

        createModalHtml(query) {
            return `
            <div id="${this.modalId}" class="ctx-streaming-modal">
                <div class="ctx-modal-content">
                    <div class="ctx-modal-header">
                        <div class="ctx-header-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 18a8 8 0 1 1 8-8 8 8 0 0 1-8 8z" opacity="0.3"/>
                                <path d="M12 6v6l4 2"/>
                            </svg>
                        </div>
                        <span class="ctx-header-text">${this.escapeHtml(this.headerText)}</span>
                    </div>
                    <div class="ctx-query-box">
                        <span class="ctx-query-label">Query</span>
                        <span class="ctx-query-text">${this.escapeHtml(query)}</span>
                    </div>
                    <div id="streaming-content" class="ctx-stream-content"></div>
                    <div class="ctx-modal-footer">
                        <div class="ctx-loading-dots">
                            <span></span><span></span><span></span>
                        </div>
                        <span class="ctx-footer-text">Processing your request...</span>
                    </div>
                </div>
            </div>`;
        }

        createDefaultStyles() {
            return `
                .ctx-streaming-modal { position: fixed; inset: 0; background: rgba(0,0,0,0.85); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); display: flex; align-items: center; justify-content: center; z-index: 10000; opacity: 0; visibility: hidden; transition: opacity 0.3s ease, visibility 0.3s ease; }
                .ctx-streaming-modal.show { opacity: 1; visibility: visible; }
                .ctx-modal-content { background: linear-gradient(145deg, rgba(15,23,42,0.98), rgba(30,41,59,0.98)); border: 1px solid rgba(99,102,241,0.25); border-radius: 16px; padding: 28px; width: 90%; max-width: 560px; max-height: 75vh; display: flex; flex-direction: column; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.05) inset; transform: scale(0.95) translateY(10px); transition: transform 0.3s ease; }
                .ctx-streaming-modal.show .ctx-modal-content { transform: scale(1) translateY(0); }
                .ctx-modal-header { display: flex; align-items: center; gap: 14px; margin-bottom: 20px; }
                .ctx-header-icon { width: 36px; height: 36px; background: linear-gradient(135deg, #6366f1, #8b5cf6); border-radius: 10px; display: flex; align-items: center; justify-content: center; animation: ctx-pulse 2s ease-in-out infinite; }
                .ctx-header-icon svg { width: 20px; height: 20px; color: #fff; animation: ctx-spin 3s linear infinite; }
                .ctx-header-text { font-size: 1.25rem; font-weight: 600; color: #f1f5f9; letter-spacing: -0.01em; }
                .ctx-query-box { background: rgba(15,23,42,0.7); border: 1px solid rgba(71,85,105,0.4); border-radius: 10px; padding: 14px 16px; margin-bottom: 20px; display: flex; align-items: baseline; gap: 10px; }
                .ctx-query-label { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #a5b4fc; flex-shrink: 0; }
                .ctx-query-text { font-size: 0.9rem; color: #cbd5e1; line-height: 1.5; word-break: break-word; }
                .ctx-stream-content { flex: 1; min-height: 180px; max-height: 280px; overflow-y: auto; background: rgba(0,0,0,0.3); border-radius: 10px; padding: 16px; margin-bottom: 16px; }
                .ctx-stream-content::-webkit-scrollbar { width: 5px; }
                .ctx-stream-content::-webkit-scrollbar-track { background: rgba(30,41,59,0.5); border-radius: 3px; }
                .ctx-stream-content::-webkit-scrollbar-thumb { background: rgba(99,102,241,0.5); border-radius: 3px; }
                .ctx-stream-content::-webkit-scrollbar-thumb:hover { background: rgba(99,102,241,0.7); }
                .ctx-stream-content.error-state { border-color: rgba(239,68,68,0.5); }
                .ctx-stream-content.error-state .streaming-step { color: #fca5a5; border-left-color: #ef4444; }
                .streaming-step { padding: 10px 14px; margin: 8px 0; font-size: 0.875rem; line-height: 1.6; color: #e2e8f0; border-left: 2px solid rgba(99,102,241,0.4); background: rgba(99,102,241,0.05); border-radius: 0 6px 6px 0; opacity: 0; transform: translateX(-8px); transition: opacity 0.25s ease, transform 0.25s ease; }
                .streaming-step.visible { opacity: 1; transform: translateX(0); }
                .ctx-modal-footer { display: flex; align-items: center; gap: 12px; padding-top: 12px; border-top: 1px solid rgba(71,85,105,0.3); }
                .ctx-loading-dots { display: flex; gap: 4px; }
                .ctx-loading-dots span { width: 6px; height: 6px; background: #6366f1; border-radius: 50%; animation: ctx-bounce 1.4s ease-in-out infinite; }
                .ctx-loading-dots span:nth-child(1) { animation-delay: -0.32s; }
                .ctx-loading-dots span:nth-child(2) { animation-delay: -0.16s; }
                .ctx-loading-dots span:nth-child(3) { animation-delay: 0s; }
                .ctx-footer-text { font-size: 0.8rem; color: #94a3b8; font-style: italic; }
                @keyframes ctx-spin { to { transform: rotate(360deg); } }
                @keyframes ctx-pulse { 0%, 100% { box-shadow: 0 0 0 0 rgba(99,102,241,0.4); } 50% { box-shadow: 0 0 0 8px rgba(99,102,241,0); } }
                @keyframes ctx-bounce { 0%, 80%, 100% { transform: scale(0.8); opacity: 0.5; } 40% { transform: scale(1.2); opacity: 1; } }
                @media (max-width: 640px) { .ctx-modal-content { width: 95%; padding: 20px; max-height: 85vh; } .ctx-header-text { font-size: 1.1rem; } .ctx-query-box { flex-direction: column; gap: 6px; } .ctx-stream-content { max-height: 220px; } }
            `;
        }

        injectStyles() {
            const styleId = 'streaming-modal-styles';
            if (!document.getElementById(styleId)) {
                const style = document.createElement('style');
                style.id = styleId;
                style.textContent = this.createDefaultStyles();
                document.head.appendChild(style);
            }
        }

        escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        isVisible() {
            return this.currentModal !== null && this.currentModal.classList.contains('show');
        }

        clearSteps() {
            const content = this.currentModal?.querySelector('#streaming-content');
            if (content) content.innerHTML = '';
        }

        destroy() { this.hide(); }
    }

    // ============================================================
    // StreamingClientWithAdapter - Wrapper with UI adapter integration
    // ============================================================
    class StreamingClientWithAdapter {
        constructor(client, adapter) {
            this.client = client;
            this.adapter = adapter;
        }

        async streamWithAdapter(url, requestData, additionalCallbacks = {}) {
            const query = requestData.query || requestData.prompt || JSON.stringify(requestData).substring(0, 50);
            if (this.adapter) this.adapter.onStreamStart(query);

            return this.client.stream(url, requestData, {
                onChunk: (chunk) => {
                    if (this.adapter) this.adapter.onChunk(chunk);
                    if (additionalCallbacks.onChunk) additionalCallbacks.onChunk(chunk);
                },
                onFinalResponse: (response) => {
                    if (this.adapter) this.adapter.onFinalResponse(response);
                    if (additionalCallbacks.onFinalResponse) additionalCallbacks.onFinalResponse(response);
                },
                onError: (error) => {
                    if (this.adapter) this.adapter.onError(error);
                    if (additionalCallbacks.onError) additionalCallbacks.onError(error);
                },
                onRetry: (attempt, maxAttempts) => {
                    if (this.adapter) this.adapter.onRetry(attempt, maxAttempts);
                    if (additionalCallbacks.onRetry) additionalCallbacks.onRetry(attempt, maxAttempts);
                },
                onComplete: () => {
                    if (this.adapter) this.adapter.onComplete();
                    if (additionalCallbacks.onComplete) additionalCallbacks.onComplete();
                },
                onAbort: () => {
                    if (this.adapter) this.adapter.onAbort();
                    if (additionalCallbacks.onAbort) additionalCallbacks.onAbort();
                }
            });
        }

        stream(url, requestData, callbacks = {}) {
            return this.client.stream(url, requestData, callbacks);
        }

        abort() {
            this.client.abort();
            if (this.adapter) this.adapter.onAbort();
        }

        reset() { this.client.reset(); }
        isStreaming() { return this.client.isStreaming(); }
        getClient() { return this.client; }
        getAdapter() { return this.adapter; }

        setAdapter(adapter) {
            if (this.adapter) this.adapter.destroy();
            this.adapter = adapter;
        }

        destroy() {
            this.client.reset();
            if (this.adapter) this.adapter.destroy();
        }
    }

    // ============================================================
    // StreamingClientBuilder - Builder Pattern for StreamingClient
    // ============================================================
    class StreamingClientBuilder {
        constructor() {
            this.config = {};
            this.adapter = null;
        }

        withMarkers(markers) {
            this.config.markers = { ...this.config.markers, ...markers };
            return this;
        }

        withRetry(options) {
            this.config.streaming = { ...this.config.streaming, ...options };
            return this;
        }

        withAdapter(adapter) {
            this.adapter = adapter;
            return this;
        }

        withModalUI(options = {}) {
            this.adapter = new ModalUIAdapter(options);
            return this;
        }

        withSimpleProgress(container, options = {}) {
            this.adapter = new SimpleProgressAdapter({ container, ...options });
            return this;
        }

        withConsoleOutput(options = {}) {
            this.adapter = new ConsoleAdapter(options);
            return this;
        }

        build() {
            const client = new StreamingClient(this.config);
            return new StreamingClientWithAdapter(client, this.adapter);
        }
    }

    // ============================================================
    // Export to global namespace
    // ============================================================
    const ContexaStreaming = {
        UIAdapter,
        StreamingClient,
        ConsoleAdapter,
        SimpleProgressAdapter,
        ModalUIAdapter,
        StreamingClientBuilder,
        StreamingClientWithAdapter
    };

    // Browser environment
    if (typeof window !== 'undefined') {
        window.ContexaStreaming = ContexaStreaming;
        // Also expose classes globally for convenience
        window.UIAdapter = UIAdapter;
        window.StreamingClient = StreamingClient;
        window.ConsoleAdapter = ConsoleAdapter;
        window.SimpleProgressAdapter = SimpleProgressAdapter;
        window.ModalUIAdapter = ModalUIAdapter;
        window.StreamingClientBuilder = StreamingClientBuilder;
        window.StreamingClientWithAdapter = StreamingClientWithAdapter;
    }

    // CommonJS environment
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = ContexaStreaming;
    }

})(typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : this);
