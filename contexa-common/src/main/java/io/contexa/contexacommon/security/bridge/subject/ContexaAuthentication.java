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
package io.contexa.contexacommon.security.bridge.subject;

import org.springframework.lang.Nullable;

import java.time.Instant;
import java.util.Objects;

/**
 * How the application signed the user of a request in, as the application states it: the method, whether more than one
 * factor was verified, when, and at which assurance. Every part is optional, and Contexa shows the decision only what is
 * stated. An application that signs in with Spring Security but carries no standard claim for it (a form login) may put
 * this value in its {@code Authentication}'s details.
 * <pre>
 * ContexaAuthentication.of("PASSWORD+OTP").mfa(true).authenticatedAt(loginAt)
 * </pre>
 * Instances are immutable: every setter returns a new one.
 */
public final class ContexaAuthentication {

    /** The longest method or assurance text Contexa keeps. */
    public static final int MAX_LENGTH = 64;

    @Nullable
    private final String method;
    @Nullable
    private final Boolean mfa;
    @Nullable
    private final Instant authenticatedAt;
    @Nullable
    private final String assurance;

    private ContexaAuthentication(@Nullable String method, @Nullable Boolean mfa, @Nullable Instant authenticatedAt,
                                  @Nullable String assurance) {
        this.method = method;
        this.mfa = mfa;
        this.authenticatedAt = authenticatedAt;
        this.assurance = assurance;
    }

    /**
     * A sign-in by a method the application names, such as {@code PASSWORD}, {@code PASSWORD+OTP} or {@code SSO};
     * {@code null} when the application states no method.
     */
    public static ContexaAuthentication of(@Nullable String method) {
        return new ContexaAuthentication(method, null, null, null);
    }

    /** The same sign-in, stating whether more than one factor was verified. */
    public ContexaAuthentication mfa(boolean verified) {
        return new ContexaAuthentication(method, verified, authenticatedAt, assurance);
    }

    /** The same sign-in, stating when it happened. */
    public ContexaAuthentication authenticatedAt(@Nullable Instant at) {
        return new ContexaAuthentication(method, mfa, at, assurance);
    }

    /** The same sign-in, stating its assurance level, such as {@code AAL2}. */
    public ContexaAuthentication assurance(@Nullable String level) {
        return new ContexaAuthentication(method, mfa, authenticatedAt, level);
    }

    @Nullable
    public String getMethod() {
        return method;
    }

    @Nullable
    public Boolean getMfa() {
        return mfa;
    }

    @Nullable
    public Instant getAuthenticatedAt() {
        return authenticatedAt;
    }

    @Nullable
    public String getAssurance() {
        return assurance;
    }

    /** Whether the value states nothing at all. */
    public boolean isEmpty() {
        return method == null && mfa == null && authenticatedAt == null && assurance == null;
    }

    /**
     * The same sign-in with the method and the assurance Contexa can keep: a text longer than {@link #MAX_LENGTH} or
     * with a control character is left out, since it reaches the decision's prompt.
     */
    ContexaAuthentication kept() {
        return new ContexaAuthentication(ContexaSubject.cleanText(method, MAX_LENGTH), mfa, authenticatedAt,
                ContexaSubject.cleanText(assurance, MAX_LENGTH));
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof ContexaAuthentication that
                && Objects.equals(method, that.method)
                && Objects.equals(mfa, that.mfa)
                && Objects.equals(authenticatedAt, that.authenticatedAt)
                && Objects.equals(assurance, that.assurance);
    }

    @Override
    public int hashCode() {
        return Objects.hash(method, mfa, authenticatedAt, assurance);
    }

    @Override
    public String toString() {
        return "ContexaAuthentication[method=" + method + ", mfa=" + mfa + ", authenticatedAt=" + authenticatedAt
                + ", assurance=" + assurance + "]";
    }
}
