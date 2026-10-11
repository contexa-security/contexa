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
package io.contexa.contexaidentity.security.handler.login;

import io.contexa.contexacommon.security.bridge.AuthenticationMethodReferences;
import io.contexa.contexacommon.security.bridge.BridgeObjectExtractor;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.security.zerotrust.ZeroTrustAuthenticationToken;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.RestAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthentication;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Records the facts of a login on the authentication the identity module completes, as {@link LoginFactsDetails}.
 * The methods come from the login flow itself (its steps and its own tokens), never from a guess.
 */
public final class LoginFactsRecorder {

    /** Factor context attribute set when the Zero Trust challenge flow started the MFA. */
    public static final String CHALLENGE_INITIATED_ATTRIBUTE = "challengeInitiated";

    private LoginFactsRecorder() {
    }

    /** The method of a login step named by its {@code AuthType}, or null when the step is not a login method. */
    @Nullable
    public static String methodOfStep(@Nullable String authTypeName) {
        if (authTypeName == null) {
            return null;
        }
        return switch (authTypeName.trim().toUpperCase(Locale.ROOT)) {
            case "FORM", "REST", "MFA_FORM", "MFA_REST" -> AuthenticationMethodReferences.PASSWORD;
            case "OTT", "MFA_OTT" -> AuthenticationMethodReferences.ONE_TIME_CODE;
            case "PASSKEY", "MFA_PASSKEY" -> AuthenticationMethodReferences.PASSKEY;
            case "RECOVERY_CODE" -> AuthenticationMethodReferences.RECOVERY_CODE;
            default -> null;
        };
    }

    /**
     * The method of an authentication produced by one of the identity module's login flows, or null for any other
     * authentication (a Zero Trust adjusted token is not a login).
     */
    @Nullable
    public static String methodOf(@Nullable Authentication authentication) {
        if (authentication == null || authentication instanceof ZeroTrustAuthenticationToken) {
            return null;
        }
        if (authentication instanceof RestAuthenticationToken
                || authentication instanceof UsernamePasswordAuthenticationToken) {
            return AuthenticationMethodReferences.PASSWORD;
        }
        if (authentication instanceof OneTimeTokenAuthenticationToken) {
            return AuthenticationMethodReferences.ONE_TIME_CODE;
        }
        if (authentication instanceof WebAuthnAuthentication) {
            return AuthenticationMethodReferences.PASSKEY;
        }
        return null;
    }

    /** Records a login completed with one method on the authentication the login flow produced. */
    public static void recordSingleFactor(@Nullable Authentication authentication, @Nullable HttpServletRequest request) {
        String method = methodOf(authentication);
        if (method != null) {
            record(authentication, request, List.of(method));
        }
    }

    /**
     * Records what an MFA flow completed. A login: the first step's method and every verified factor. A Zero Trust
     * challenge: the session's login stays as it was and the time the challenge was passed is added.
     */
    public static void recordFinal(@Nullable Authentication finalAuthentication,
                                   @Nullable HttpServletRequest request,
                                   @Nullable FactorContext factorContext) {
        if (factorContext != null && Boolean.TRUE.equals(factorContext.getAttribute(CHALLENGE_INITIATED_ATTRIBUTE))) {
            recordChallenge(finalAuthentication, request, factorContext);
            return;
        }
        List<String> methods = new ArrayList<>();
        if (factorContext != null) {
            addIfPresent(methods, methodOf(factorContext.getPrimaryAuthentication()));
            for (AuthenticationStepConfig step : factorContext.getCompletedFactors()) {
                addIfPresent(methods, methodOfStep(step.getType()));
            }
        }
        if (methods.isEmpty()) {
            addIfPresent(methods, methodOf(finalAuthentication));
        }
        if (!methods.isEmpty()) {
            record(finalAuthentication, request, methods);
        }
    }

    /** The details source of a login flow whose method is fixed, such as form login. */
    public static AuthenticationDetailsSource<HttpServletRequest, LoginFactsDetails> detailsSource(String method) {
        return request -> details(request, List.of(method));
    }

    static LoginFactsDetails details(@Nullable HttpServletRequest request, List<String> methods) {
        String remoteAddress = request != null ? request.getRemoteAddr() : null;
        HttpSession session = request != null ? request.getSession(false) : null;
        return new LoginFactsDetails(remoteAddress, session != null ? session.getId() : null, methods,
                observedTime(request));
    }

    /**
     * The time of the login request on the same clock as the other facts of the request (its observed time), so the
     * login and the requests that follow it are not on two clocks.
     */
    private static Instant observedTime(@Nullable HttpServletRequest request) {
        Instant observedAt = request != null ? RequestInfoExtractor.extractObservedAt(request) : null;
        return observedAt != null ? observedAt : Instant.now();
    }

    private static void recordChallenge(@Nullable Authentication finalAuthentication,
                                        @Nullable HttpServletRequest request,
                                        FactorContext factorContext) {
        if (!(finalAuthentication instanceof AbstractAuthenticationToken token)) {
            return;
        }
        String remoteAddress = request != null ? request.getRemoteAddr() : null;
        HttpSession session = request != null ? request.getSession(false) : null;
        String sessionId = session != null ? session.getId() : null;
        LoginFactsDetails login = loginOf(factorContext.getPrimaryAuthentication(), remoteAddress, sessionId);
        token.setDetails(LoginFactsDetails.challengeVerified(remoteAddress, sessionId, login, observedTime(request)));
    }

    /**
     * The login of the challenged authentication: its recorded facts, or for a request a token authenticated (whose
     * principal is the token, also when Zero Trust re-wrapped it) the login the token states in its claims.
     */
    @Nullable
    private static LoginFactsDetails loginOf(@Nullable Authentication challenged, @Nullable String remoteAddress,
                                             @Nullable String sessionId) {
        if (challenged == null) {
            return null;
        }
        if (challenged.getDetails() instanceof LoginFactsDetails facts) {
            return facts;
        }
        Object token = challenged.getPrincipal();
        return LoginFactsDetails.restored(remoteAddress, sessionId,
                BridgeObjectExtractor.extractStringSet(token, List.of(LoginFactClaims.AMR)),
                BridgeObjectExtractor.extractInstant(token, List.of(LoginFactClaims.AUTH_TIME)),
                BridgeObjectExtractor.extractString(token, List.of(LoginFactClaims.SID)));
    }

    private static void record(@Nullable Authentication authentication, @Nullable HttpServletRequest request,
                               List<String> methods) {
        if (authentication instanceof AbstractAuthenticationToken token) {
            token.setDetails(details(request, methods));
        }
    }

    private static void addIfPresent(List<String> methods, @Nullable String method) {
        if (method != null && !methods.contains(method)) {
            methods.add(method);
        }
    }
}
