/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.utils;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacommon.security.bridge.AgentSessionKey;
import io.contexa.contexacommon.security.bridge.OAuth2AuthenticationSupport;
import io.contexa.contexacommon.security.network.ClientIpResolver;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicReference;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;


@Slf4j
public class SessionFingerprintUtil {

    private static final HexFormat HEX_FORMAT = HexFormat.of();

    /**
     * Settings used until the application binds its own. Proxy validation is enabled and no proxy is
     * trusted, so forwarded headers are ignored and the socket peer address is used.
     */
    private static final TieredStrategyProperties DEFAULT_CLIENT_IP_PROPERTIES = new TieredStrategyProperties();
    private static final AtomicReference<TieredStrategyProperties> BOUND_CLIENT_IP_PROPERTIES =
            new AtomicReference<>();

    /**
     * Binds the trusted proxy settings that {@link RequestInfoExtractor} applies to security events.
     * The context binding hash is computed by filters, handlers and repositories that cannot inject
     * configuration, so the binding keeps every caller on the same client IP trust rule.
     */
    public static void bindClientIpResolution(TieredStrategyProperties properties) {
        BOUND_CLIENT_IP_PROPERTIES.set(properties);
    }

    /**
     * Removes the binding made with the given settings. A binding registered later by another
     * application context is kept.
     */
    public static void unbindClientIpResolution(TieredStrategyProperties properties) {
        BOUND_CLIENT_IP_PROPERTIES.compareAndSet(properties, null);
    }

    public static String generateFingerprint(SecurityEvent event) {
        if (event == null) {
            log.error("[SessionFingerprint] Event is null, returning default fingerprint");
            return "UNKNOWN";
        }

        StringBuilder fingerprint = new StringBuilder();

        if (event.getUserAgent() != null) {
            fingerprint.append("UA:").append(hashString(event.getUserAgent())).append("|");
        }

        if (event.getSourceIp() != null) {
            fingerprint.append("IP:").append(hashString(event.getSourceIp())).append("|");
        }

        int hourOfDay = event.getLocalTimestamp().getHour();
        fingerprint.append("TH:").append(hourOfDay).append("|");

        fingerprint.append("SV:").append(event.getSeverity() != null ? event.getSeverity().toString() : "INFO").append("|");

        if (event.getMetadata() != null && !event.getMetadata().isEmpty()) {
            String metadataHash = hashString(event.getMetadata().toString());
            fingerprint.append("MD:").append(metadataHash).append("|");
        }

        return hashString(fingerprint.toString());
    }

    private static String hashString(String input) {
        if (input == null || input.isEmpty()) {
            return "00000000";
        }

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            String fullHash = HEX_FORMAT.formatHex(hash);
            return fullHash.substring(0, 8);
        } catch (NoSuchAlgorithmException e) {
            log.error("[SessionFingerprint] SHA-256 algorithm not available", e);
            return input.hashCode() + "";
        }
    }

    private static final String CONSOLE_CONTEXT = "console:";
    private static final String CONTEXT_BINDING_HASH_ATTR = "contexa.contextBindingHash";
    /** Set while the binding reads the request's security context (see {@link #currentAuthentication}). */
    private static final String READING_CONTEXT_ATTR = "contexa.contextBindingHash.readingContext";

    /** The binding of the request for the authentication of its security context. */
    public static String generateContextBindingHash(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String cached = (String) request.getAttribute(CONTEXT_BINDING_HASH_ATTR);
        if (cached != null) {
            return cached;
        }
        if (request.getAttribute(READING_CONTEXT_ATTR) != null) {
            // Reached again while the security context loads: the binding of the servlet session, not kept, so the
            // binding of the loaded authentication is the one the request keeps.
            return generateContextBindingHash(request.getRequestedSessionId(), extractClientIp(request),
                    request.getHeader("User-Agent"));
        }
        return generateContextBindingHash(request, currentAuthentication(request));
    }

    /**
     * The binding of the request for the given authentication, kept for the rest of the request. Code that loads the
     * security context passes the authentication it loaded: reading the context there would load it again.
     */
    public static String generateContextBindingHash(HttpServletRequest request, @Nullable Authentication authentication) {
        if (request == null) {
            return null;
        }
        String cached = (String) request.getAttribute(CONTEXT_BINDING_HASH_ATTR);
        if (cached != null) {
            return cached;
        }
        String hash = generateContextBindingHash(
                sessionOf(authentication, request.getRequestedSessionId()),
                extractClientIp(request),
                request.getHeader("User-Agent")
        );
        if (hash != null) {
            request.setAttribute(CONTEXT_BINDING_HASH_ATTR, hash);
        }
        return hash;
    }

    /**
     * Context binding hash the client presents on its next request. Authentication success can rotate the session
     * id within the current request (session fixation protection), so the current session id wins over the
     * requested one. Without a session the requested id is kept, as in {@link #generateContextBindingHash(HttpServletRequest)}.
     */
    /**
     * Context binding hash the client presents on its next request after a sign-in of a token state. That request is a
     * bearer call, which is one session with the login its token carries ({@code sid}), whether or not it carries the
     * servlet session a step of the login may have created, so the sign-in is bound to that login and not to the
     * servlet session of the login request. Without a token session this is
     * {@link #generateNextRequestContextBindingHash(HttpServletRequest)}.
     *
     * @param tokenSessionId the login the token states as its {@code sid}, null in a session state
     */
    public static String generateNextRequestContextBindingHash(HttpServletRequest request, @Nullable String tokenSessionId) {
        if (request == null) {
            return null;
        }
        if (tokenSessionId == null || tokenSessionId.isBlank()) {
            return generateNextRequestContextBindingHash(request);
        }
        return generateContextBindingHash(tokenSessionId.trim(), extractClientIp(request), request.getHeader("User-Agent"));
    }

    public static String generateNextRequestContextBindingHash(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        HttpSession session = request.getSession(false);
        String sessionId = session != null ? session.getId() : request.getRequestedSessionId();
        return generateContextBindingHash(sessionOf(currentAuthentication(request), sessionId),
                extractClientIp(request), request.getHeader("User-Agent"));
    }

    /**
     * The session the binding names: an agent's or a client's own token request is bound to the agent's session
     * (A1-11), so agents on one network and one user agent do not share a binding; a person's token request to the login
     * its token carries, as {@link RequestIdentity#sessionId} names it, whether or not the request also holds a servlet
     * session; any other request to the given servlet session.
     */
    private static String sessionOf(@Nullable Authentication authentication, String servletSession) {
        String agentSession = AgentSessionKey.of(authentication);
        if (agentSession != null) {
            return agentSession;
        }
        String tokenSession = OAuth2AuthenticationSupport.tokenAttribute(
                authentication, OAuth2AuthenticationSupport.SESSION_ID_CLAIM);
        return tokenSession != null ? tokenSession : servletSession;
    }

    /**
     * The authentication of the request's security context. Reading the context can load it, and loading it computes
     * the binding (the zero trust check of a session's context), so a read made while the context loads returns null
     * instead of loading it again.
     */
    @Nullable
    private static Authentication currentAuthentication(HttpServletRequest request) {
        if (request.getAttribute(READING_CONTEXT_ATTR) != null) {
            return null;
        }
        request.setAttribute(READING_CONTEXT_ATTR, Boolean.TRUE);
        try {
            return SecurityContextHolder.getContext().getAuthentication();
        } finally {
            request.removeAttribute(READING_CONTEXT_ATTR);
        }
    }

    public static String generateContextBindingHash(String sessionId, String ip, String userAgent) {
        if (sessionId == null && ip == null && userAgent == null) {
            return null;
        }
        String raw = "CTX:" + (sessionId != null ? sessionId : "")
                + "|" + (ip != null ? ip : "")
                + "|" + (userAgent != null ? userAgent : "");
        return hashStringLong(raw);
    }

    private static String hashStringLong(String input) {
        if (input == null || input.isEmpty()) {
            return "0000000000000000";
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return HEX_FORMAT.formatHex(hash).substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            log.error("[SessionFingerprint] SHA-256 algorithm not available", e);
            return String.valueOf(input.hashCode());
        }
    }

    /**
     * Resolves the client IP with the same trust rule as {@link RequestInfoExtractor}: forwarded
     * headers are honored only when the peer is a configured trusted proxy, or for probes carrying
     * the runtime capability issued by this server.
     */
    public static String extractClientIp(HttpServletRequest request) {
        return RequestInfoExtractor.extractClientIp(request, clientIpSecurity());
    }

    /**
     * Q-24: whether the request came through a proxy Contexa was not told about. It carries X-Forwarded-For while no
     * proxy is trusted, so the peer may well be that proxy and every user behind it has this one address. With proxies
     * named, a peer outside them is a client and its header proves nothing; with the validation off the header is
     * believed anyway. Neither leaves the address in doubt.
     * <p>
     * The header alone proves nothing, as anyone can send it. Only a peer on a private network, a link-local address or the
     * machine itself can be such a proxy here: nobody on the internet connects from those addresses, and the socket's
     * address cannot be forged. A public peer that sends the header is taken for what it is, a client. A peer this answers
     * true for may still be a client on that network, so the answer may ease a limit of the address and never lift one.
     */
    public static boolean forwardedWithoutTrustedProxy(@Nullable HttpServletRequest request) {
        if (request == null || request.getHeader("X-Forwarded-For") == null) {
            return false;
        }
        TieredStrategyProperties.Security security = clientIpSecurity();
        return security.isTrustedProxyValidationEnabled()
                && (security.getTrustedProxies() == null || security.getTrustedProxies().isEmpty())
                && ClientIpResolver.isPrivateOrLoopback(request.getRemoteAddr());
    }

    /**
     * The context a passed verification of a BLOCK is kept for. A console session shares its HTTP session, address and
     * client with the application's user of that browser, and that user may be named like the console's key, so the
     * console's context stands apart: what the application's chain verified answers nothing in the console.
     */
    @Nullable
    public static String verificationContext(HttpServletRequest request) {
        String contextBindingHash = generateContextBindingHash(request);
        return contextBindingHash != null && ConsoleSession.of(request) ? CONSOLE_CONTEXT + contextBindingHash
                : contextBindingHash;
    }

    private static TieredStrategyProperties.Security clientIpSecurity() {
        TieredStrategyProperties bound = BOUND_CLIENT_IP_PROPERTIES.get();
        TieredStrategyProperties.Security security = bound != null ? bound.getSecurity() : null;
        return security != null ? security : DEFAULT_CLIENT_IP_PROPERTIES.getSecurity();
    }
}
