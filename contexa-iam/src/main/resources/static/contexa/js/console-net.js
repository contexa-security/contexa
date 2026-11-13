/*
 * Network helper of the console pages, loaded by every page through common-head after the MFA SDK (so it wraps the
 * SDK's fetch and sees the answer after a token renewal).
 *
 * Context path: the console scripts name their addresses as console paths (/contexa/...), without the servlet context
 * path. ContexaConsole.url() puts the context path of <meta name="contexa-context-path"> in front, and every fetch of
 * a same-origin root-relative address goes through it, so a deployment under a context path reaches the same handlers.
 *
 * Zero Trust decisions: when a decision stops a request of a page script, the page goes to the screen of the decision
 * instead of showing an empty list.
 * - A plain fetch follows the redirect of the decision filter and receives the decision screen: the page goes there.
 * - 401 with code ZERO_TRUST_CHALLENGE (a JSON request): the page goes to the challenge notice.
 * - 503 MFA_BUSY_RETRY (the challenge is being prepared by a request sent at the same moment): the request is sent
 *   again after Retry-After; the filter answers it before any handler, so nothing was done the first time.
 * - 403: the current page is asked again as a JSON request; when that answer is a challenge, the page reloads and the
 *   browser is sent to the notice.
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

    // "@{/}" renders "/" or "/ctx/"; a ";jsessionid=..." suffix is not part of the path.
    var contextPath = String(meta('contexa-context-path') || '/').split(';')[0].split('?')[0].replace(/\/+$/, '');

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
    var challengeProbe = null;

    /** Whether the session is under a challenge: the current page asked again as a JSON request answers so. */
    function underChallenge() {
        if (!challengeProbe) {
            challengeProbe = nativeFetch.call(global, global.location.href.split('#')[0], {
                method: 'GET',
                credentials: 'same-origin',
                cache: 'no-store',
                headers: { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest' }
            }).then(function (answer) {
                if (answer.redirected && isDecisionScreen(answer.url)) {
                    return true;
                }
                if (answer.status !== 401 && answer.status !== 503) {
                    return false;
                }
                return jsonOf(answer).then(function (body) {
                    return !!body && (body.code === CHALLENGE_CODE || body.error === BUSY_RETRY);
                });
            }).catch(function () {
                return false;
            }).then(function (challenged) {
                challengeProbe = null;
                return challenged;
            });
        }
        return challengeProbe;
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
                return response;
            });
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
            return underChallenge().then(function (challenged) {
                return challenged ? leaveFor(null) : response;
            });
        }
        return response;
    }

    function send(call, attempt) {
        var input = call.input instanceof Request ? call.input.clone() : call.input;
        return nativeFetch.call(global, input, call.init).then(function (response) {
            return settle(response, call, attempt);
        });
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
