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

import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * The user of a request, as the application tells Contexa (the legacy integration standard, bridge v2): the only value an
 * application hands over. A user id and a mail address are required; everything else is optional. Contexa reads nothing
 * of the application's own objects.
 * <pre>
 * ContexaSubject.of(userId, email)
 *         .displayName(name)
 *         .authentication(ContexaAuthentication.of("PASSWORD+OTP").mfa(true).authenticatedAt(loginAt))
 *         .build();
 * </pre>
 * Building never throws. A value that breaks a rule is reported in {@link #getProblems()}:
 * <ul>
 *   <li>a user id that is blank, longer than {@link #MAX_TEXT_LENGTH} or has a control character leaves the request
 *       without a Contexa identity, and the request goes on as the application has it;</li>
 *   <li>a missing or malformed mail address keeps the identity, but no verification code can be sent to it;</li>
 *   <li>an optional value that breaks its rule is left out.</li>
 * </ul>
 * Leading and trailing blanks are stripped (a control character is no blank and breaks the rule); the case of the
 * user id is kept as given.
 */
public final class ContexaSubject {

    /**
     * The request attribute an application's own servlet filter puts the user of a request under, for an application
     * that signs its users in without Spring Security:
     * {@code request.setAttribute(ContexaSubject.REQUEST_ATTRIBUTE, subject)}.
     */
    public static final String REQUEST_ATTRIBUTE = "ctxa.subject";
    /** The longest user id, mail address, organization id, tenant id, session key or authority Contexa keeps. */
    public static final int MAX_TEXT_LENGTH = 255;
    /** The longest display name Contexa keeps. */
    public static final int MAX_DISPLAY_NAME_LENGTH = 100;
    /** The most authorities Contexa keeps for one user. */
    public static final int MAX_AUTHORITIES = 256;

    @Nullable
    private final String userId;
    @Nullable
    private final String email;
    @Nullable
    private final String displayName;
    @Nullable
    private final String organizationId;
    @Nullable
    private final String tenantId;
    private final Set<String> authorities;
    @Nullable
    private final ContexaAuthentication authentication;
    @Nullable
    private final String sessionKey;
    @Nullable
    private final ContexaDelegation delegation;
    private final Set<SubjectProblem> problems;

    private ContexaSubject(Builder builder) {
        EnumSet<SubjectProblem> found = EnumSet.noneOf(SubjectProblem.class);
        this.userId = userId(builder.userId, found);
        this.email = email(builder.email, found);
        this.displayName = optional(builder.displayName, MAX_DISPLAY_NAME_LENGTH, SubjectProblem.DISPLAY_NAME_DROPPED, found);
        this.organizationId = optional(builder.organizationId, MAX_TEXT_LENGTH, SubjectProblem.ORGANIZATION_DROPPED, found);
        this.tenantId = optional(builder.tenantId, MAX_TEXT_LENGTH, SubjectProblem.TENANT_DROPPED, found);
        this.sessionKey = optional(builder.sessionKey, MAX_TEXT_LENGTH, SubjectProblem.SESSION_KEY_DROPPED, found);
        this.authorities = authorities(builder.authorities, found);
        this.authentication = authentication(builder.authentication, found);
        this.delegation = delegation(builder.delegation, found);
        this.problems = Collections.unmodifiableSet(found);
    }

    private ContexaSubject(ContexaSubject from, @Nullable String email, Set<SubjectProblem> problems) {
        this.userId = from.userId;
        this.email = email;
        this.displayName = from.displayName;
        this.organizationId = from.organizationId;
        this.tenantId = from.tenantId;
        this.authorities = from.authorities;
        this.authentication = from.authentication;
        this.sessionKey = from.sessionKey;
        this.delegation = from.delegation;
        this.problems = Collections.unmodifiableSet(problems);
    }

    /** A user by the application's user id and mail address. */
    public static Builder of(@Nullable String userId, @Nullable String email) {
        return new Builder(userId, email);
    }

    /**
     * The same user with another mail address, checked by the same rule; the problems of the other values stay. Contexa
     * uses it to give a user named without an address the address the application's mail address provider knows.
     */
    public ContexaSubject withEmail(@Nullable String address) {
        EnumSet<SubjectProblem> found = EnumSet.noneOf(SubjectProblem.class);
        found.addAll(problems);
        found.removeIf(SubjectProblem::breaksTheEmail);
        String kept = email(address, found);
        return new ContexaSubject(this, kept, found);
    }

    /** The user id, or {@code null} when it breaks the rule (the request then has no Contexa identity). */
    @Nullable
    public String getUserId() {
        return userId;
    }

    /** The mail address, or {@code null} when it is missing or malformed. */
    @Nullable
    public String getEmail() {
        return email;
    }

    @Nullable
    public String getDisplayName() {
        return displayName;
    }

    @Nullable
    public String getOrganizationId() {
        return organizationId;
    }

    @Nullable
    public String getTenantId() {
        return tenantId;
    }

    /** The application's authorities, as given and in order; Contexa does not interpret them. */
    public Set<String> getAuthorities() {
        return authorities;
    }

    @Nullable
    public ContexaAuthentication getAuthentication() {
        return authentication;
    }

    /** What names one sign-in and stays the same when a token is renewed, for an application without sessions. */
    @Nullable
    public String getSessionKey() {
        return sessionKey;
    }

    @Nullable
    public ContexaDelegation getDelegation() {
        return delegation;
    }

    /** What breaks the standard in this value; empty when nothing does. */
    public Set<SubjectProblem> getProblems() {
        return problems;
    }

    /** Whether the user id keeps the rule, so the request has a Contexa identity. */
    public boolean hasUserId() {
        return userId != null;
    }

    /** Whether a mail address a verification code can be sent to is known. */
    public boolean hasEmail() {
        return email != null;
    }

    @Nullable
    private static String userId(@Nullable String value, Set<SubjectProblem> found) {
        String trimmed = value != null ? value.strip() : "";
        if (trimmed.isEmpty()) {
            found.add(SubjectProblem.USER_ID_BLANK);
            return null;
        }
        if (trimmed.length() > MAX_TEXT_LENGTH) {
            found.add(SubjectProblem.USER_ID_TOO_LONG);
            return null;
        }
        if (hasControlCharacter(trimmed)) {
            found.add(SubjectProblem.USER_ID_CONTROL_CHARACTER);
            return null;
        }
        return trimmed;
    }

    @Nullable
    private static String email(@Nullable String value, Set<SubjectProblem> found) {
        String trimmed = value != null ? value.strip() : "";
        if (trimmed.isEmpty()) {
            found.add(SubjectProblem.EMAIL_MISSING);
            return null;
        }
        if (trimmed.length() > MAX_TEXT_LENGTH) {
            found.add(SubjectProblem.EMAIL_TOO_LONG);
            return null;
        }
        if (!isAddress(trimmed)) {
            found.add(SubjectProblem.EMAIL_MALFORMED);
            return null;
        }
        return trimmed;
    }

    /** One {@code @} between a local part and a domain, no blank or control character, no empty domain label. */
    static boolean isAddress(String address) {
        int at = address.indexOf('@');
        if (at <= 0 || at != address.lastIndexOf('@') || at == address.length() - 1) {
            return false;
        }
        for (int index = 0; index < address.length(); index++) {
            char character = address.charAt(index);
            if (Character.isWhitespace(character) || Character.isISOControl(character)) {
                return false;
            }
        }
        String domain = address.substring(at + 1);
        return !domain.startsWith(".") && !domain.endsWith(".") && !domain.contains("..");
    }

    @Nullable
    private static String optional(@Nullable String value, int maximum, SubjectProblem problem, Set<SubjectProblem> found) {
        if (value == null || value.strip().isEmpty()) {
            return null;
        }
        String clean = cleanText(value, maximum);
        if (clean == null) {
            found.add(problem);
        }
        return clean;
    }

    private static Set<String> authorities(Collection<String> values, Set<SubjectProblem> found) {
        LinkedHashSet<String> kept = new LinkedHashSet<>();
        boolean trimmed = false;
        for (String value : values) {
            if (value == null || value.strip().isEmpty()) {
                continue;
            }
            String clean = cleanText(value, MAX_TEXT_LENGTH);
            if (clean == null || (kept.size() >= MAX_AUTHORITIES && !kept.contains(clean))) {
                trimmed = true;
                continue;
            }
            kept.add(clean);
        }
        if (trimmed) {
            found.add(SubjectProblem.AUTHORITIES_TRIMMED);
        }
        return Collections.unmodifiableSet(kept);
    }

    @Nullable
    private static ContexaAuthentication authentication(@Nullable ContexaAuthentication value, Set<SubjectProblem> found) {
        if (value == null) {
            return null;
        }
        ContexaAuthentication kept = value.kept();
        if (!Objects.equals(kept.getMethod(), trimmedOrNull(value.getMethod()))
                || !Objects.equals(kept.getAssurance(), trimmedOrNull(value.getAssurance()))) {
            found.add(SubjectProblem.AUTHENTICATION_FIELD_DROPPED);
        }
        return kept.isEmpty() ? null : kept;
    }

    @Nullable
    private static ContexaDelegation delegation(@Nullable ContexaDelegation value, Set<SubjectProblem> found) {
        if (value == null) {
            return null;
        }
        if (!value.namesAnAgent()) {
            found.add(SubjectProblem.DELEGATION_DROPPED);
            return null;
        }
        return value;
    }

    @Nullable
    private static String trimmedOrNull(@Nullable String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.strip();
        return trimmed.isEmpty() ? null : trimmed;
    }

    /**
     * A text as Contexa keeps it: trimmed, and {@code null} when it is blank, longer than {@code maximum} or carries a
     * control character.
     */
    @Nullable
    static String cleanText(@Nullable String value, int maximum) {
        String trimmed = trimmedOrNull(value);
        if (trimmed == null || trimmed.length() > maximum || hasControlCharacter(trimmed)) {
            return null;
        }
        return trimmed;
    }

    private static boolean hasControlCharacter(String text) {
        for (int index = 0; index < text.length(); index++) {
            if (Character.isISOControl(text.charAt(index))) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof ContexaSubject that
                && Objects.equals(userId, that.userId)
                && Objects.equals(email, that.email)
                && Objects.equals(displayName, that.displayName)
                && Objects.equals(organizationId, that.organizationId)
                && Objects.equals(tenantId, that.tenantId)
                && authorities.equals(that.authorities)
                && Objects.equals(authentication, that.authentication)
                && Objects.equals(sessionKey, that.sessionKey)
                && Objects.equals(delegation, that.delegation)
                && problems.equals(that.problems);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, email, displayName, organizationId, tenantId, authorities, authentication, sessionKey,
                delegation, problems);
    }

    /** The user id and what is known, never the mail address itself. */
    @Override
    public String toString() {
        return "ContexaSubject[userId=" + userId + ", email=" + (email != null ? "present" : "missing")
                + ", authorities=" + authorities.size() + ", problems=" + problems + "]";
    }

    /** Builds a subject; building never throws. */
    public static final class Builder {

        @Nullable
        private final String userId;
        @Nullable
        private final String email;
        @Nullable
        private String displayName;
        @Nullable
        private String organizationId;
        @Nullable
        private String tenantId;
        private Collection<String> authorities = Set.of();
        @Nullable
        private ContexaAuthentication authentication;
        @Nullable
        private String sessionKey;
        @Nullable
        private ContexaDelegation delegation;

        private Builder(@Nullable String userId, @Nullable String email) {
            this.userId = userId;
            this.email = email;
        }

        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }

        public Builder organizationId(@Nullable String organizationId) {
            this.organizationId = organizationId;
            return this;
        }

        public Builder tenantId(@Nullable String tenantId) {
            this.tenantId = tenantId;
            return this;
        }

        public Builder authorities(@Nullable Collection<String> authorities) {
            this.authorities = authorities != null ? authorities : Set.of();
            return this;
        }

        public Builder authentication(@Nullable ContexaAuthentication authentication) {
            this.authentication = authentication;
            return this;
        }

        public Builder sessionKey(@Nullable String sessionKey) {
            this.sessionKey = sessionKey;
            return this;
        }

        public Builder delegation(@Nullable ContexaDelegation delegation) {
            this.delegation = delegation;
            return this;
        }

        public ContexaSubject build() {
            return new ContexaSubject(this);
        }
    }
}
