/**
 * Contexa LLM Library - Bundle
 *
 * A reusable library for LLM analysis with streaming and non-streaming support.
 *
 * @version 2.0.0
 * @license MIT
 *
 * @example Streaming analysis
 * const result = await ContexaLLM.analyzeStreaming('/api/llm/stream', { query: 'Hello' });
 *
 * @example Non-streaming analysis
 * const result = await ContexaLLM.analyze('/api/llm/query', { query: 'Hello' });
 */
(function(global) {
    'use strict';

    // ============================================================
    // UIAdapter - Base Class for UI Adapters
    // ============================================================
    class UIAdapter {
        constructor(options = {}) {
            this.options = options;
        }

        onStart(query) {}
        onChunk(chunk) {}
        onGeneratingResult() {}
        onFinalResponse(response) {}
        onError(error) {
            console.error('LLM error:', error);
        }
        onRetry(attempt, maxAttempts) {}
        onComplete() {}
        onAbort() {}
        destroy() {}
    }

    // ============================================================
    // StreamingClient - SSE Streaming Client
    // ============================================================
    class StreamingClient {
        static DEFAULT_CONFIG = {
            markers: {
                FINAL_RESPONSE: '###FINAL_RESPONSE###',
                GENERATING_RESULT: '###GENERATING_RESULT###',
                DONE: '[DONE]',
                ERROR_PREFIX: 'ERROR:'
            },
            maxRetries: 3,
            retryDelay: 1000,
            retryMultiplier: 1.5,
            timeoutMs: 300000
        };

        constructor(config = {}) {
            this.config = { ...StreamingClient.DEFAULT_CONFIG, ...config };
            if (config.markers) {
                this.config.markers = { ...StreamingClient.DEFAULT_CONFIG.markers, ...config.markers };
            }
            this.abortController = null;
            this.isAborted = false;
            this.retryCount = 0;
            this.finalResponseReceived = false;
            this.finalResponseBuffer = '';
        }

        async stream(url, requestData, callbacks = {}) {
            return new Promise((resolve, reject) => {
                let finalResponse = null;
                let finalResponseMarkerReceived = false;

                this.startStreaming(url, requestData, {
                    onChunk: (chunk) => {
                        if (callbacks.onChunk) callbacks.onChunk(chunk);
                    },
                    onGeneratingResult: () => {
                        if (callbacks.onGeneratingResult) callbacks.onGeneratingResult();
                    },
                    onFinalResponse: (data) => {
                        finalResponseMarkerReceived = true;
                        if (callbacks.onFinalResponse) callbacks.onFinalResponse(data);
                    },
                    onComplete: () => {
                        if (finalResponseMarkerReceived && this.finalResponseBuffer) {
                            finalResponse = this.parseFinalResponse(this.finalResponseBuffer);
                        }
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
                    onStreamError: callbacks.onStreamError
                });
            });
        }

        async startStreaming(url, requestData, callbacks) {
            this.isAborted = false;
            this.abortController = new AbortController();
            this.finalResponseReceived = false;
            this.finalResponseBuffer = '';

            const timeoutId = setTimeout(() => {
                if (!this.isAborted) {
                    this.abortController.abort();
                    if (callbacks.onError) {
                        callbacks.onError(new Error(`Request timeout after ${this.config.timeoutMs}ms`));
                    }
                }
            }, this.config.timeoutMs);

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

                if (this.retryCount < this.config.maxRetries) {
                    this.retryCount++;
                    const delay = this.config.retryDelay *
                        Math.pow(this.config.retryMultiplier, this.retryCount - 1);

                    if (callbacks.onRetry) callbacks.onRetry(this.retryCount, this.config.maxRetries);
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

            if (this.finalResponseReceived) {
                this.finalResponseBuffer += data;
                return;
            }

            if (data.includes(markers.FINAL_RESPONSE)) {
                this.finalResponseReceived = true;
                this.finalResponseBuffer = data;
                if (callbacks.onFinalResponse) callbacks.onFinalResponse(data);
                return;
            }

            if (data.includes(markers.GENERATING_RESULT)) {
                if (callbacks.onGeneratingResult) callbacks.onGeneratingResult();
                return;
            }

            if (callbacks.onChunk) callbacks.onChunk(data);
        }

        parseFinalResponse(data) {
            if (!data) return null;

            try {
                const markers = this.config.markers;
                if (data.includes(markers.FINAL_RESPONSE)) {
                    const markerIndex = data.lastIndexOf(markers.FINAL_RESPONSE);
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
            let cleaned = jsonString.trim();
            if (!cleaned) throw new Error('Empty JSON input');

            if (cleaned.startsWith('```json')) {
                cleaned = cleaned.replace(/^```json\s*/, '').replace(/```\s*$/, '').trim();
            } else if (cleaned.startsWith('```')) {
                cleaned = cleaned.replace(/^```\s*/, '').replace(/```\s*$/, '').trim();
            }

            const firstBrace = cleaned.indexOf('{');
            let lastBrace = cleaned.lastIndexOf('}');

            if (firstBrace !== -1 && lastBrace === -1) {
                let braceCount = 0, bracketCount = 0, inString = false, escapeNext = false;
                for (let i = firstBrace; i < cleaned.length; i++) {
                    const char = cleaned[i];
                    if (escapeNext) { escapeNext = false; continue; }
                    if (char === '\\') { escapeNext = true; continue; }
                    if (char === '"' && !escapeNext) { inString = !inString; continue; }
                    if (!inString) {
                        if (char === '{') braceCount++;
                        else if (char === '}') braceCount--;
                        else if (char === '[') bracketCount++;
                        else if (char === ']') bracketCount--;
                    }
                }
                for (let i = 0; i < bracketCount; i++) cleaned += ']';
                for (let i = 0; i < braceCount; i++) cleaned += '}';
                lastBrace = cleaned.lastIndexOf('}');
            }

            if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
                cleaned = cleaned.substring(firstBrace, lastBrace + 1);
            }

            return JSON.parse(cleaned);
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

        sleep(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        }
    }

    // ============================================================
    // SyncClient - Non-streaming HTTP Client
    // ============================================================
    class SyncClient {
        static DEFAULT_CONFIG = {
            timeoutMs: 300000
        };

        constructor(config = {}) {
            this.config = { ...SyncClient.DEFAULT_CONFIG, ...config };
            this.abortController = null;
        }

        async request(url, requestData, callbacks = {}) {
            this.abortController = new AbortController();

            const timeoutId = setTimeout(() => {
                this.abortController.abort();
                if (callbacks.onTimeout) callbacks.onTimeout();
            }, this.config.timeoutMs);

            try {
                const response = await fetch(url, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json',
                        ...this.getCsrfHeaders()
                    },
                    body: JSON.stringify(requestData),
                    signal: this.abortController.signal
                });

                clearTimeout(timeoutId);

                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }

                const result = await response.json();
                if (callbacks.onSuccess) callbacks.onSuccess(result);
                return result;

            } catch (error) {
                clearTimeout(timeoutId);
                if (error.name === 'AbortError') {
                    if (callbacks.onAbort) callbacks.onAbort();
                    return null;
                }
                if (callbacks.onError) callbacks.onError(error);
                throw error;
            }
        }

        getCsrfHeaders() {
            if (typeof document === 'undefined') return {};
            const csrfToken = document.querySelector('meta[name="_csrf"]')?.content;
            const csrfHeader = document.querySelector('meta[name="_csrf_header"]')?.content;
            return (csrfToken && csrfHeader) ? { [csrfHeader]: csrfToken } : {};
        }

        abort() {
            if (this.abortController) {
                this.abortController.abort();
                this.abortController = null;
            }
        }
    }

    // ============================================================
    // ModalUIAdapter - Modal-based Streaming UI Adapter
    // ============================================================
    class ModalUIAdapter extends UIAdapter {
        constructor(options = {}) {
            super(options);
            this.modalId = options.modalId || 'llm-modal';
            this.headerText = options.headerText || 'AI Analyzing...';
            this.hideDelay = options.hideDelay || 300;
            this.currentModal = null;
            this.initialMessageShown = false;
            this.generatingResultShown = false;
            this.initialLoadingText = options.initialLoadingText || 'LLM 분석 시작...';
            this.generatingResultText = options.generatingResultText || '결과 데이터 생성중...';
            this.analysisCompleteText = options.analysisCompleteText || 'LLM 분석 완료';
            this.finalCompleteText = options.finalCompleteText || 'AI 분석 완료!';
        }

        onStart(query) {
            this.hide();
            this.injectStyles();
            this.initialMessageShown = false;
            this.generatingResultShown = false;
            const modalHtml = this.createModalHtml(query);
            document.body.insertAdjacentHTML('beforeend', modalHtml);
            this.currentModal = document.getElementById(this.modalId);
            requestAnimationFrame(() => {
                if (this.currentModal) this.currentModal.classList.add('show');
            });
            this.initialMessageShown = true;
            this.addLoadingStep(this.initialLoadingText, 'ctx-initial-loading');
        }

        onChunk(chunk) {
            this.addStep(chunk);
        }

        onGeneratingResult() {
            if (this.initialMessageShown) {
                this.removeLoadingStep('ctx-initial-loading');
                this.initialMessageShown = false;
                this.addCompletedStep(this.analysisCompleteText);
            }
            if (!this.generatingResultShown) {
                this.generatingResultShown = true;
                this.addLoadingStep(this.generatingResultText, 'ctx-generating-result');
            }
        }

        onFinalResponse(response) {
            if (this.generatingResultShown) {
                this.removeLoadingStep('ctx-generating-result');
                this.generatingResultShown = false;
            }
            this.addCompletedStep(this.finalCompleteText);
            this.updateHeader('Complete');
        }

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

        addLoadingStep(message, id) {
            const content = this.currentModal?.querySelector('#streaming-content');
            if (!content) return;
            const step = document.createElement('div');
            step.id = id;
            step.className = 'streaming-step ctx-loading-step';
            step.innerHTML = `
                <div class="ctx-loading-spinner"></div>
                <span>${this.escapeHtml(message)}</span>
            `;
            content.appendChild(step);
            requestAnimationFrame(() => {
                step.classList.add('visible');
                content.scrollTop = content.scrollHeight;
            });
        }

        addCompletedStep(message) {
            const content = this.currentModal?.querySelector('#streaming-content');
            if (!content) return;
            const step = document.createElement('div');
            step.className = 'streaming-step ctx-completed-step';
            step.innerHTML = `
                <div class="ctx-completed-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
                        <path d="M20 6L9 17l-5-5"/>
                    </svg>
                </div>
                <span>${this.escapeHtml(message)}</span>
            `;
            content.appendChild(step);
            requestAnimationFrame(() => {
                step.classList.add('visible');
                content.scrollTop = content.scrollHeight;
            });
        }

        removeLoadingStep(id) {
            const step = this.currentModal?.querySelector(`#${id}`);
            if (step) {
                step.classList.remove('visible');
                setTimeout(() => {
                    if (step.parentNode) step.parentNode.removeChild(step);
                }, 200);
            }
        }

        updateHeader(text) {
            const header = this.currentModal?.querySelector('.ctx-header-text');
            if (header) header.textContent = text;
        }

        createModalHtml(query) {
            return `
            <div id="${this.modalId}" class="ctx-llm-modal">
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
                .ctx-llm-modal { position: fixed; inset: 0; background: rgba(0,0,0,0.85); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); display: flex; align-items: center; justify-content: center; z-index: 10000; opacity: 0; visibility: hidden; transition: opacity 0.3s ease, visibility 0.3s ease; }
                .ctx-llm-modal.show { opacity: 1; visibility: visible; }
                .ctx-modal-content { background: linear-gradient(145deg, rgba(15,23,42,0.98), rgba(30,41,59,0.98)); border: 1px solid rgba(99,102,241,0.25); border-radius: 16px; padding: 28px; width: 90%; max-width: 560px; max-height: 75vh; display: flex; flex-direction: column; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.05) inset; transform: scale(0.95) translateY(10px); transition: transform 0.3s ease; }
                .ctx-llm-modal.show .ctx-modal-content { transform: scale(1) translateY(0); }
                .ctx-modal-header { display: flex; align-items: center; gap: 14px; margin-bottom: 20px; }
                .ctx-header-icon { width: 36px; height: 36px; background: linear-gradient(135deg, #6366f1, #8b5cf6); border-radius: 10px; display: flex; align-items: center; justify-content: center; animation: ctx-pulse 2s ease-in-out infinite; }
                .ctx-header-icon svg { width: 20px; height: 20px; color: #fff; animation: ctx-spin 3s linear infinite; }
                .ctx-header-text { font-size: 1.25rem; font-weight: 600; color: #f1f5f9; letter-spacing: -0.01em; }
                .ctx-query-box { background: rgba(15,23,42,0.7); border: 1px solid rgba(71,85,105,0.4); border-radius: 10px; padding: 14px 16px; margin-bottom: 20px; display: flex; align-items: baseline; gap: 10px; }
                .ctx-query-label { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #a5b4fc; flex-shrink: 0; }
                .ctx-query-text { font-size: 0.9rem; color: #cbd5e1; line-height: 1.5; word-break: break-word; }
                .ctx-stream-content { flex: 1; min-height: 234px; max-height: 364px; overflow-y: auto; background: rgba(0,0,0,0.3); border-radius: 10px; padding: 16px; margin-bottom: 16px; }
                .ctx-stream-content::-webkit-scrollbar { width: 5px; }
                .ctx-stream-content::-webkit-scrollbar-track { background: rgba(30,41,59,0.5); border-radius: 3px; }
                .ctx-stream-content::-webkit-scrollbar-thumb { background: rgba(99,102,241,0.5); border-radius: 3px; }
                .ctx-stream-content.error-state { border-color: rgba(239,68,68,0.5); }
                .ctx-stream-content.error-state .streaming-step { color: #fca5a5; border-left-color: #ef4444; }
                .streaming-step { padding: 10px 14px; margin: 8px 0; font-size: 0.875rem; line-height: 1.6; color: #e2e8f0; border-left: 2px solid rgba(99,102,241,0.4); background: rgba(99,102,241,0.05); border-radius: 0 6px 6px 0; opacity: 0; transform: translateX(-8px); transition: opacity 0.25s ease, transform 0.25s ease; }
                .streaming-step.visible { opacity: 1; transform: translateX(0); }
                .ctx-loading-step { display: flex; align-items: center; gap: 10px; border-left-color: rgba(139,92,246,0.6); background: rgba(139,92,246,0.08); }
                .ctx-loading-spinner { width: 16px; height: 16px; border: 2px solid rgba(139,92,246,0.3); border-top-color: #8b5cf6; border-radius: 50%; animation: ctx-spin 1s linear infinite; flex-shrink: 0; }
                .ctx-completed-step { display: flex; align-items: center; gap: 10px; border-left-color: rgba(34,197,94,0.6); background: rgba(34,197,94,0.08); }
                .ctx-completed-icon { width: 18px; height: 18px; background: linear-gradient(135deg, #22c55e, #16a34a); border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; animation: ctx-check-pop 0.4s ease-out; }
                .ctx-completed-icon svg { width: 12px; height: 12px; color: #fff; }
                @keyframes ctx-check-pop { 0% { transform: scale(0); opacity: 0; } 50% { transform: scale(1.2); } 100% { transform: scale(1); opacity: 1; } }
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
                @media (max-width: 640px) { .ctx-modal-content { width: 95%; padding: 20px; max-height: 85vh; } .ctx-header-text { font-size: 1.1rem; } .ctx-query-box { flex-direction: column; gap: 6px; } .ctx-stream-content { max-height: 286px; } }
            `;
        }

        injectStyles() {
            const styleId = 'ctx-llm-modal-styles';
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

        destroy() { this.hide(); }
    }

    // ============================================================
    // InlineLoadingAdapter - Inline Loading UI for Non-streaming
    // ============================================================
    class InlineLoadingAdapter extends UIAdapter {
        constructor(options = {}) {
            super(options);
            this.container = options.container || document.body;
            this.loadingText = options.loadingText || 'AI 분석 중...';
            this.subText = options.subText || '잠시만 기다려 주세요';
            this.loadingElement = null;
        }

        onStart(query) {
            this.destroy();
            this.injectStyles();

            this.loadingElement = document.createElement('div');
            this.loadingElement.className = 'ctx-inline-loader';
            this.loadingElement.innerHTML = `
                <div class="ctx-inline-loader-content">
                    <div class="ctx-inline-spinner"></div>
                    <div class="ctx-inline-text">${this.escapeHtml(this.loadingText)}</div>
                    <div class="ctx-inline-subtext">${this.escapeHtml(this.subText)}</div>
                </div>
            `;
            this.container.appendChild(this.loadingElement);
        }

        onError(error) {
            if (this.loadingElement) {
                const textEl = this.loadingElement.querySelector('.ctx-inline-text');
                if (textEl) {
                    textEl.textContent = `Error: ${error.message || error}`;
                    textEl.classList.add('ctx-inline-error');
                }
            }
        }

        onComplete() { this.destroy(); }
        onAbort() { this.destroy(); }

        destroy() {
            if (this.loadingElement && this.loadingElement.parentNode) {
                this.loadingElement.parentNode.removeChild(this.loadingElement);
                this.loadingElement = null;
            }
        }

        injectStyles() {
            const styleId = 'ctx-inline-loader-styles';
            if (document.getElementById(styleId)) return;

            const style = document.createElement('style');
            style.id = styleId;
            style.textContent = `
                .ctx-inline-loader {
                    position: absolute;
                    inset: 0;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    background: rgba(15, 23, 42, 0.7);
                    backdrop-filter: blur(4px);
                    z-index: 100;
                }
                .ctx-inline-loader-content {
                    text-align: center;
                    color: #e2e8f0;
                }
                .ctx-inline-spinner {
                    width: 48px;
                    height: 48px;
                    border: 4px solid rgba(99, 102, 241, 0.3);
                    border-top-color: #6366f1;
                    border-radius: 50%;
                    margin: 0 auto 16px;
                    animation: ctx-inline-spin 1s linear infinite;
                }
                .ctx-inline-text {
                    font-size: 14px;
                    font-weight: 500;
                    margin-bottom: 8px;
                }
                .ctx-inline-text.ctx-inline-error {
                    color: #fca5a5;
                }
                .ctx-inline-subtext {
                    font-size: 12px;
                    color: #94a3b8;
                }
                @keyframes ctx-inline-spin {
                    to { transform: rotate(360deg); }
                }
            `;
            document.head.appendChild(style);
        }

        escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    }

    // ============================================================
    // ContexaLLM - Main API
    // ============================================================
    const ContexaLLM = {
        UIAdapter,
        StreamingClient,
        SyncClient,
        ModalUIAdapter,
        InlineLoadingAdapter,

        /**
         * Perform non-streaming LLM analysis
         * @param {string} url - API endpoint
         * @param {Object} requestData - Request data (query field expected)
         * @param {Object} options - Configuration options
         * @returns {Promise<Object>} Parsed JSON response
         */
        async analyze(url, requestData, options = {}) {
            const config = {
                timeoutMs: options.timeoutMs || 300000,
                showLoading: options.showLoading !== false,
                container: options.container || null,
                loadingText: options.loadingText || 'AI 분석 중...',
                subText: options.subText || '잠시만 기다려 주세요',
                onComplete: options.onComplete || null,
                onError: options.onError || null
            };

            let adapter = null;

            if (config.showLoading && config.container) {
                adapter = new InlineLoadingAdapter({
                    container: config.container,
                    loadingText: config.loadingText,
                    subText: config.subText
                });
                adapter.onStart(requestData.query || '');
            }

            const client = new SyncClient({ timeoutMs: config.timeoutMs });

            try {
                const result = await client.request(url, requestData);
                if (config.onComplete) config.onComplete(result);
                return result;

            } catch (error) {
                if (adapter) adapter.onError(error);
                if (config.onError) config.onError(error);
                throw error;

            } finally {
                if (adapter) adapter.destroy();
            }
        },

        /**
         * Perform streaming LLM analysis with modal UI
         * @param {string} url - Streaming API endpoint
         * @param {Object} requestData - Request data (query field expected)
         * @param {Object} options - Configuration options
         * @returns {Promise<Object>} Parsed final response
         */
        async analyzeStreaming(url, requestData, options = {}) {
            const config = {
                modalTitle: options.modalTitle || 'AI Analyzing...',
                initialLoadingText: options.initialLoadingText || 'LLM 분석 시작...',
                analysisCompleteText: options.analysisCompleteText || 'LLM 분석 완료',
                generatingResultText: options.generatingResultText || '결과 데이터 생성중...',
                finalCompleteText: options.finalCompleteText || 'AI 분석 완료!',
                autoHideDelay: options.autoHideDelay || 1500,
                timeoutMs: options.timeoutMs || 300000,
                onProgress: options.onProgress || null,
                onComplete: options.onComplete || null,
                onError: options.onError || null
            };

            const adapter = new ModalUIAdapter({
                headerText: config.modalTitle,
                initialLoadingText: config.initialLoadingText,
                generatingResultText: config.generatingResultText,
                analysisCompleteText: config.analysisCompleteText,
                finalCompleteText: config.finalCompleteText
            });

            const client = new StreamingClient({ timeoutMs: config.timeoutMs });
            const query = requestData.query || '';
            adapter.onStart(query);

            let errorHandled = false;

            try {
                const result = await client.stream(url, requestData, {
                    onChunk: (chunk) => {
                        adapter.onChunk(chunk);
                        if (config.onProgress) config.onProgress(chunk);
                    },
                    onGeneratingResult: () => {
                        adapter.onGeneratingResult();
                    },
                    onFinalResponse: (data) => {
                        adapter.onFinalResponse(data);
                    },
                    onError: (error) => {
                        if (!errorHandled) {
                            errorHandled = true;
                            adapter.onError(error);
                            if (config.onError) config.onError(error);
                        }
                    }
                });

                if (config.onComplete) config.onComplete(result);
                setTimeout(() => adapter.hide(), config.autoHideDelay);
                return result;

            } catch (error) {
                if (!errorHandled) {
                    adapter.onError(error);
                    setTimeout(() => adapter.hide(), config.autoHideDelay);
                    if (config.onError) config.onError(error);
                } else {
                    setTimeout(() => adapter.hide(), config.autoHideDelay);
                }
                throw error;
            }
        }
    };

    // Browser environment
    if (typeof window !== 'undefined') {
        window.ContexaLLM = ContexaLLM;
    }

    // CommonJS environment
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = ContexaLLM;
    }

})(typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : this);
