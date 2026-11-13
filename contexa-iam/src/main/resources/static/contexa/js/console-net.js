/*
 * Network helper of the console pages, loaded by every page through common-head after the MFA SDK (so it wraps the
 * SDK's fetch and sees the answer after a token renewal).
 *
 * Context path: the console scripts name their addresses as console paths (/contexa/...), without the servlet context
 * path. ContexaConsole.url() puts the context path (taken from this script's own address) in front, and every fetch of
 * a same-origin root-relative address goes through it, so a deployment under a context path reaches the same handlers.
 *
 * Zero Trust decisions: when a decision stops a request of a page script, the page goes to the screen of the decision
 * instead of showing an empty list.
 * - A plain fetch follows the redirect of the decision filter and receives the decision screen: the page goes there.
 * - 401 with code ZERO_TRUST_CHALLENGE (a JSON request): the page goes to the challenge notice.
 * - 503 MFA_BUSY_RETRY (the challenge is being prepared by a request sent at the same moment): the request is sent
 *   again after Retry-After; the filter answers it before any handler, so nothing was done the first time.
 * - Any other 401, and 403: the current page is asked again as a JSON request; when that answer is a challenge, the page
 *   reloads and the browser is sent to the notice.
 *
 * What a page script may leave unsaid is told by a notice at the top of the page: the session ended (the page asked
 * again no longer opens), or the server could not be reached (taken away by the next answer).
 *
 * ContexaConsole.fetchJson() is the call for page scripts that show the reason of a failure: it rejects with the
 * message of the server, or with a sentence saying the server could not be reached.
 */
(function (global) {
    'use strict';

    if (global.ContexaConsole || typeof global.fetch !== 'function') {
        return;
    }

    var CONSOLE_PATH = /^\/contexa(?:[\/?#]|$)/;
    var DECISION_SCREENS = '/contexa/zero-trust/';
    var CHALLENGE_CODE = 'ZERO_TRUST_CHALLENGE';
    var BUSY_RETRY = 'MFA_BUSY_RETRY';
    var MAX_BUSY_RETRIES = 3;
    var MAX_RETRY_AFTER_SECONDS = 10;

    function meta(name) {
        var element = document.querySelector('meta[name="' + name + '"]');
        return element ? element.getAttribute('content') : null;
    }

    var SCRIPT_PATH = '/contexa/js/console-net.js';

    /**
     * The context path, read from this script's own address (rendered with @{/contexa/js/console-net.js}): "" or
     * "/ctx". A link to "/" is no source for it, because a host may rewrite that one link (contexa-site sends "/" to its
     * language home, "/ko/") while it leaves every console path as it is.
     */
    function scriptContextPath() {
        var script = document.currentScript;
        if (!script || String(script.getAttribute('src') || '').indexOf(SCRIPT_PATH) < 0) {
            script = document.querySelector('script[src*="' + SCRIPT_PATH + '"]');
        }
        if (!script) {
            return '';
        }
        var path;
        try {
            path = new URL(script.getAttribute('src'), global.location.href).pathname;
        } catch (e) {
            return '';
        }
        // A ";jsessionid=..." suffix is not part of the path.
        path = path.split(';')[0];
        var at = path.lastIndexOf(SCRIPT_PATH);
        return at > 0 ? path.slice(0, at).replace(/\/+$/, '') : '';
    }

    var contextPath = scriptContextPath();

    function text(name, fallback) {
        var value = meta('contexa-net-' + name);
        return value ? value : fallback;
    }

    function withContextPath(path) {
        if (!contextPath || path.charAt(0) !== '/' || path.charAt(1) === '/') {
            return path;
        }
        if (CONSOLE_PATH.test(path)) {
            // A console path carries the context path only when a console path follows it; this also holds when the
            // context path is itself /contexa.
            var rest = path.indexOf(contextPath) === 0 ? path.slice(contextPath.length) : '';
            return CONSOLE_PATH.test(rest) ? path : contextPath + path;
        }
        var carries = path === contextPath || /^[\/?#]/.test(path.slice(contextPath.length))
            && path.indexOf(contextPath) === 0;
        return carries ? path : contextPath + path;
    }

    /** The address with the context path: root-relative and same-origin absolute addresses; others as given. */
    function url(value) {
        if (value === null || value === undefined) {
            return value;
        }
        var address = String(value);
        var origin = global.location.origin;
        if (origin && address.indexOf(origin + '/') === 0) {
            return origin + withContextPath(address.slice(origin.length));
        }
        return withContextPath(address);
    }

    /** The path without the context path, as the console scripts name it. */
    function pathWithinApp(path) {
        var value = String(path || '');
        if (!contextPath || value.indexOf(contextPath) !== 0) {
            return value;
        }
        var rest = value.slice(contextPath.length);
        if (rest === '') {
            return '/';
        }
        return /^[\/?#]/.test(rest) ? rest : value;
    }

    function sameOrigin(address) {
        try {
            return new URL(address, global.location.href).origin === global.location.origin;
        } catch (e) {
            return false;
        }
    }

    function isDecisionScreen(address) {
        try {
            var target = new URL(address, global.location.href);
            return target.origin === global.location.origin
                && pathWithinApp(target.pathname).indexOf(DECISION_SCREENS) === 0;
        } catch (e) {
            return false;
        }
    }

    function onDecisionScreen() {
        return pathWithinApp(global.location.pathname).indexOf(DECISION_SCREENS) === 0;
    }

    function jsonOf(response) {
        var type = response.headers.get('content-type') || '';
        if (type.indexOf('json') === -1) {
            return Promise.resolve(null);
        }
        return response.clone().json().catch(function () {
            return null;
        });
    }

    var leaving = false;

    /** Sends the page to the target (or reloads it) once; the caller's promise stays pending while the page goes. */
    function leaveFor(target) {
        if (!leaving) {
            leaving = true;
            if (target) {
                global.location.assign(target);
            } else {
                global.location.reload();
            }
        }
        return new Promise(function () {
        });
    }

    var nativeFetch = global.fetch;
    var pageProbe = null;

    function pathOf(address) {
        try {
            return new URL(address, global.location.href).pathname;
        } catch (e) {
            return null;
        }
    }

    /** Whether an answer asks for a verification step (a challenge, a block to resolve) rather than a sign-in. */
    function asksVerification(body) {
        return !!body && (body.code === CHALLENGE_CODE || body.error === BUSY_RETRY || !!body.mfaUrl);
    }

    /**
     * The state of the session, read by asking the current page again as a JSON request: "challenge" when a verification
     * stands in its way, "ended" when it no longer opens for want of a sign-in (a 401, or a redirect to another page),
     * "open" otherwise. A refused request alone does not say which: a 401 or 403 may also be the answer of one handler.
     */
    function pageState() {
        if (!pageProbe) {
            pageProbe = nativeFetch.call(global, global.location.href.split('#')[0], {
                method: 'GET',
                credentials: 'same-origin',
                cache: 'no-store',
                headers: { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest' }
            }).then(function (answer) {
                if (answer.redirected && isDecisionScreen(answer.url)) {
                    return 'challenge';
                }
                if (answer.redirected && pathOf(answer.url) !== global.location.pathname) {
                    return 'ended';
                }
                if (answer.status !== 401 && answer.status !== 503) {
                    return 'open';
                }
                return jsonOf(answer).then(function (body) {
                    if (asksVerification(body)) {
                        return 'challenge';
                    }
                    return answer.status === 401 ? 'ended' : 'open';
                });
            }).catch(function () {
                return 'open';
            }).then(function (state) {
                pageProbe = null;
                return state;
            });
        }
        return pageProbe;
    }

    /**
     * A refused request (401, or 403 as a stale CSRF token after the session ended is answered) settles by the state of
     * the session: a verification reloads the page, which the browser follows to it; an ended session is told on the
     * page, with a link that opens the page again and so reaches the sign-in of whatever guards it.
     */
    function afterRefusal(response) {
        return pageState().then(function (state) {
            if (state === 'challenge') {
                return leaveFor(null);
            }
            if (state === 'ended') {
                notice('session', text('session-ended', 'Your session has ended. Sign in again to go on.'),
                    { text: text('sign-in', 'Sign in'), href: global.location.href.split('#')[0] });
            }
            return response;
        });
    }

    function retryAfterMillis(response, body) {
        var seconds = Number(response.headers.get('Retry-After'));
        if (!(seconds > 0) && body && Number(body.retryAfterSeconds) > 0) {
            seconds = Number(body.retryAfterSeconds);
        }
        if (!(seconds > 0)) {
            seconds = 1;
        }
        return Math.min(seconds, MAX_RETRY_AFTER_SECONDS) * 1000;
    }

    function replayable(call) {
        var body = call.init && call.init.body;
        return !(typeof ReadableStream !== 'undefined' && body instanceof ReadableStream);
    }

    function settle(response, call, attempt) {
        if (!call.sameOrigin || onDecisionScreen()) {
            return response;
        }
        if (response.redirected && isDecisionScreen(response.url)) {
            return leaveFor(response.url);
        }
        if (response.status === 401) {
            return jsonOf(response).then(function (body) {
                if (body && body.code === CHALLENGE_CODE) {
                    return leaveFor(body.challengeNoticeUrl || body.mfaUrl || null);
                }
                return afterRefusal(response);
            });
        }
        if (response.ok) {
            clearNotice('offline');
        }
        if (response.status === 503) {
            return jsonOf(response).then(function (body) {
                if (!body || body.error !== BUSY_RETRY || attempt >= MAX_BUSY_RETRIES || !replayable(call)) {
                    return response;
                }
                return new Promise(function (resolve) {
                    setTimeout(resolve, retryAfterMillis(response, body));
                }).then(function () {
                    return send(call, attempt + 1);
                });
            });
        }
        if (response.status === 403) {
            return afterRefusal(response);
        }
        return response;
    }

    function send(call, attempt) {
        var input = call.input instanceof Request ? call.input.clone() : call.input;
        return nativeFetch.call(global, input, call.init).then(function (response) {
            return settle(response, call, attempt);
        }, function (error) {
            if (call.sameOrigin && !(error && error.name === 'AbortError')) {
                notice('offline', text('offline',
                    'The server could not be reached. Check the network connection and try again.'), null);
            }
            throw error;
        });
    }

    var NOTICE_ID = 'contexa-net-notice';

    /**
     * A notice at the top of the page for what a page script may leave unsaid: the session ended, or the server could not
     * be reached. One notice at a time, the newer replacing the older; a page script's own message stays as it is.
     */
    function notice(kind, message, link) {
        if (!document.body) {
            return;
        }
        var box = document.getElementById(NOTICE_ID);
        if (!box) {
            box = document.createElement('div');
            box.id = NOTICE_ID;
            box.setAttribute('role', 'alert');
            box.style.cssText = 'position:fixed;top:12px;left:50%;transform:translateX(-50%);z-index:10000;max-width:90%;'
                + 'padding:10px 16px;border-radius:8px;background:#7f1d1d;color:#fff;font-size:14px;'
                + 'box-shadow:0 4px 12px rgba(0,0,0,.3)';
            document.body.appendChild(box);
        }
        box.setAttribute('data-kind', kind);
        box.textContent = message;
        if (link) {
            var anchor = document.createElement('a');
            anchor.href = link.href;
            anchor.textContent = link.text;
            anchor.style.cssText = 'margin-left:8px;color:#fff;text-decoration:underline;font-weight:600';
            box.appendChild(anchor);
        }
    }

    /** Takes the notice away once what it said is over (an answer arrived after the server could not be reached). */
    function clearNotice(kind) {
        var box = document.getElementById(NOTICE_ID);
        if (box && box.getAttribute('data-kind') === kind) {
            box.parentNode.removeChild(box);
        }
    }

    function prepare(input, init) {
        var address;
        if (typeof Request !== 'undefined' && input instanceof Request) {
            address = url(input.url);
            if (address !== input.url) {
                input = new Request(address, input);
            }
        } else if (typeof input === 'string' || (typeof URL !== 'undefined' && input instanceof URL)) {
            address = url(String(input));
            input = address;
        } else {
            address = String(input);
        }
        return { input: input, init: init, sameOrigin: sameOrigin(address) };
    }

    global.fetch = function (input, init) {
        return send(prepare(input, init), 0);
    };

    /** The reason of a failed answer: the message of the server, or a sentence with the status. */
    function reasonOf(response) {
        var fallback = text('failed', 'The request failed (HTTP {0}).').replace('{0}', String(response.status));
        return response.clone().text().then(function (body) {
            if (!body) {
                return fallback;
            }
            try {
                var data = JSON.parse(body);
                var reason = data && (data.message || data.error || data.detail || data.title);
                return reason ? String(reason) : fallback;
            } catch (e) {
                // An HTML error page is not a sentence a person can read in a toast.
                return /^\s*</.test(body) ? fallback : body.slice(0, 300);
            }
        }).catch(function () {
            return fallback;
        });
    }

    function networkFailure(error) {
        if (error && error.name === 'AbortError') {
            return error;
        }
        var failure = new Error(text('offline',
            'The server could not be reached. Check the network connection and try again.'));
        failure.cause = error;
        failure.offline = true;
        return failure;
    }

    /**
     * Sends the request and resolves its JSON body (null for an answer without JSON). A failed answer rejects with the
     * server's message (error.status holds the status), an unreachable server with a sentence saying so.
     */
    function fetchJson(address, options) {
        return global.fetch(address, options).then(function (response) {
            if (!response.ok) {
                return reasonOf(response).then(function (reason) {
                    var failure = new Error(reason);
                    failure.status = response.status;
                    throw failure;
                });
            }
            return jsonOf(response);
        }, function (error) {
            throw networkFailure(error);
        });
    }

    global.ContexaConsole = {
        contextPath: contextPath,
        url: url,
        pathWithinApp: pathWithinApp,
        fetchJson: fetchJson,
        reasonOf: reasonOf
    };
})(window);
