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
import io.contexa.contexacore.autonomous.execution.ExecutionSubjectTypes;
import org.springframework.lang.Nullable;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.io.Serial;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Authentication details carrying the facts of a session's login: the login method, its RFC 8176 references, whether
 * the session has completed MFA (in its login or by passing a Zero Trust challenge), when the login was completed, the
 * assurance level, the principal type, when the session last passed a challenge, and an identifier of the login (one
 * per login, kept when a challenge is passed; a token state carries it as its session). The bridge reads them by name
 * (the authentication stamp's standard fields), so the engine sees the login as it happened instead of a class name.
 */
public class LoginFactsDetails extends WebAuthenticationDetails {

    @Serial
    private static final long serialVersionUID = 1L;

    private final String authenticationType;
    private final List<String> amr;
    private final Boolean mfaCompleted;
    private final Instant authenticationTime;
    private final String authenticationAssurance;
    private final String principalType;
    private final Instant challengeVerifiedAt;
    /**
     * The identifier of this login. Not named loginId: the bridge reads a principal id by member name and takes
     * loginId as a host's account id, so a per-login identifier under that name became the principal (P2
     * correction 7).
     */
    private final String signInId;
    /**
     * The type name of the MFA flow the login completed (such as {@code mfa_admin}), or {@code null} for a login of a
     * single flow. An MFA flow's scope accepts its own logins also when its policy asked no factor.
     */
    @Nullable
    private final String signInFlow;

    public LoginFactsDetails(@Nullable String remoteAddress, @Nullable String sessionId,
                             List<String> methods, Instant authenticationTime) {
        this(remoteAddress, sessionId, methods, authenticationTime, UUID.randomUUID().toString());
    }

    private LoginFactsDetails(@Nullable String remoteAddress, @Nullable String sessionId,
                              List<String> methods, Instant authenticationTime, String signInId) {
        super(remoteAddress, sessionId);
        this.authenticationType = AuthenticationMethodReferences.methodName(methods);
        this.amr = AuthenticationMethodReferences.referencesOf(methods);
        this.mfaCompleted = this.amr.contains(AuthenticationMethodReferences.MULTIPLE_FACTOR_REFERENCE);
        this.authenticationTime = Objects.requireNonNull(authenticationTime, "authenticationTime");
        this.authenticationAssurance = AuthenticationMethodReferences.assuranceOf(methods);
        this.principalType = ExecutionSubjectTypes.HUMAN_USER;
        this.challengeVerifiedAt = null;
        this.signInId = Objects.requireNonNull(signInId, "signInId");
        this.signInFlow = null;
    }

    /**
     * The login a token issued for it states in its claims (the {@code amr} methods, the {@code auth_time} and the
     * login identifier {@code sid}), for a request that token authenticated; null when the claims state no login.
     * A token issued before the login identifier existed gets a new one.
     */
    @Nullable
    public static LoginFactsDetails restored(@Nullable String remoteAddress, @Nullable String sessionId,
                                             @Nullable Collection<String> amr, @Nullable Instant authenticationTime,
                                             @Nullable String signInId) {
        List<String> methods = AuthenticationMethodReferences.methodsOf(amr);
        if (authenticationTime == null || methods.isEmpty()) {
            return null;
        }
        return new LoginFactsDetails(remoteAddress, sessionId, methods, authenticationTime,
                signInId != null && !signInId.isBlank() ? signInId.trim() : UUID.randomUUID().toString());
    }

    private LoginFactsDetails(@Nullable String remoteAddress, @Nullable String sessionId,
                              @Nullable LoginFactsDetails login, Instant challengeVerifiedAt) {
        super(remoteAddress, sessionId);
        this.authenticationType = login != null ? login.authenticationType : null;
        this.amr = login != null ? login.amr : List.of();
        this.mfaCompleted = Boolean.TRUE;
        this.authenticationTime = login != null ? login.authenticationTime : null;
        this.authenticationAssurance = login != null ? login.authenticationAssurance : null;
        this.principalType = ExecutionSubjectTypes.HUMAN_USER;
        this.challengeVerifiedAt = Objects.requireNonNull(challengeVerifiedAt, "challengeVerifiedAt");
        this.signInId = login != null ? login.signInId : UUID.randomUUID().toString();
        this.signInFlow = login != null ? login.signInFlow : null;
    }

    /**
     * The facts after the session passed a Zero Trust challenge: the login stays as it was (unknown when the login
     * left no facts) and the session now has a completed MFA with its time.
     */
    public static LoginFactsDetails challengeVerified(@Nullable String remoteAddress, @Nullable String sessionId,
                                                      @Nullable LoginFactsDetails login, Instant verifiedAt) {
        return new LoginFactsDetails(remoteAddress, sessionId, login, verifiedAt);
    }

    private LoginFactsDetails(LoginFactsDetails login) {
        this(null, null, login, login.signInFlow);
    }

    private LoginFactsDetails(@Nullable String remoteAddress, @Nullable String sessionId, LoginFactsDetails login,
                              @Nullable String signInFlow) {
        super(remoteAddress, sessionId);
        this.authenticationType = login.authenticationType;
        this.amr = login.amr;
        this.mfaCompleted = login.mfaCompleted;
        this.authenticationTime = login.authenticationTime;
        this.authenticationAssurance = login.authenticationAssurance;
        this.principalType = login.principalType;
        this.challengeVerifiedAt = login.challengeVerifiedAt;
        this.signInId = login.signInId;
        this.signInFlow = signInFlow;
    }

    /** The same facts, of the same request, as the login of the given MFA flow. */
    public LoginFactsDetails ofFlow(@Nullable String flowTypeName) {
        return new LoginFactsDetails(getRemoteAddress(), getSessionId(), this, flowTypeName);
    }

    /** The facts a token states, with the MFA flow it names (see {@link #getSignInFlow()}). */
    @Nullable
    public static LoginFactsDetails restored(@Nullable String remoteAddress, @Nullable String sessionId,
                                             @Nullable Collection<String> amr, @Nullable Instant authenticationTime,
                                             @Nullable String signInId, @Nullable String signInFlow) {
        LoginFactsDetails login = restored(remoteAddress, sessionId, amr, authenticationTime, signInId);
        return login != null && signInFlow != null && !signInFlow.isBlank() ? login.ofFlow(signInFlow.trim()) : login;
    }

    /** The same facts without the request they came with: a store does not keep its address or its servlet session. */
    public LoginFactsDetails withoutRequest() {
        return new LoginFactsDetails(this);
    }

    public String getAuthenticationType() {
        return authenticationType;
    }

    public List<String> getAmr() {
        return amr;
    }

    public Boolean getMfaCompleted() {
        return mfaCompleted;
    }

    public Instant getAuthenticationTime() {
        return authenticationTime;
    }

    public String getAuthenticationAssurance() {
        return authenticationAssurance;
    }

    public String getPrincipalType() {
        return principalType;
    }

    @Nullable
    public Instant getChallengeVerifiedAt() {
        return challengeVerifiedAt;
    }

    public String getSignInId() {
        return signInId;
    }

    @Nullable
    public String getSignInFlow() {
        return signInFlow;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof LoginFactsDetails that) || !super.equals(other)) {
            return false;
        }
        return Objects.equals(authenticationType, that.authenticationType)
                && Objects.equals(amr, that.amr)
                && Objects.equals(authenticationTime, that.authenticationTime)
                && Objects.equals(challengeVerifiedAt, that.challengeVerifiedAt)
                && Objects.equals(signInId, that.signInId)
                && Objects.equals(signInFlow, that.signInFlow);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), authenticationType, amr, authenticationTime, challengeVerifiedAt, signInId, signInFlow);
    }
}
