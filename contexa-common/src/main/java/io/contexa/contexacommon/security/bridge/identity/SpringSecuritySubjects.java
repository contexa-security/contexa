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
package io.contexa.contexacommon.security.bridge.identity;

import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexacommon.security.bridge.AuthenticationMethodReferences;
import io.contexa.contexacommon.security.bridge.BridgeInstants;
import io.contexa.contexacommon.security.bridge.OAuth2AuthenticationSupport;
import io.contexa.contexacommon.security.bridge.authentication.BridgeAuthenticationToken;
import io.contexa.contexacommon.security.bridge.subject.ContexaAuthentication;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import io.contexa.contexacommon.security.bridge.subject.SubjectProblem;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserEmailProvider;
import io.contexa.contexacommon.security.context.OfficialContextField;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.Nullable;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.Principal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The user of a signed-in Spring Security authentication of a standard kind, read the way Spring Security names it
 * (branch S of the legacy integration standard). The id is {@link Authentication#getName()}; the mail address comes
 * from the sources the application set; the session key is the {@code sid} of an access token only (an OAuth2 or
 * OpenID Connect login keeps its servlet session, as before); the sign-in facts come from what the application stated
 * ({@link ContexaAuthentication} in the details), else from the standard claims ({@code amr}, {@code auth_time},
 * {@code acr}), else from the official context attributes. Nothing of an application's own principal object is read.
 */
final class SpringSecuritySubjects {

    static final String CLAIM_SOURCE_PREFIX = "claim:";
    static final String PROVIDER_SOURCE = "provider";

    private SpringSecuritySubjects() {
    }

    /** Whether Contexa reads the user of this authentication itself, from the kinds Spring Security names a user by. */
    static boolean standardKind(Authentication authentication) {
        Object principal = authentication.getPrincipal();
        return principal instanceof UserDetails
                || principal instanceof AuthenticatedPrincipal
                || principal instanceof Principal
                || principal instanceof CharSequence
                || authentication instanceof BridgeAuthenticationToken
                || OAuth2AuthenticationSupport.isOAuth2Authentication(authentication);
    }

    /** The subject of a signed-in authentication of a standard kind. */
    static ContexaSubject read(Authentication authentication, HttpServletRequest request, List<String> emailSources,
                               @Nullable BridgeUserEmailProvider emailProvider, Problems problems) {
        Map<String, Object> claims = OAuth2AuthenticationSupport.userClaims(authentication);
        String userId = authentication.getName();
        return ContexaSubject.of(userId, email(userId, claims, emailSources, emailProvider, problems))
                .displayName(text(claims.get("name")))
                .authorities(authorities(authentication))
                .authentication(facts(authentication, claims, request))
                .sessionKey(OAuth2AuthenticationSupport.tokenAttribute(authentication, OAuth2AuthenticationSupport.SESSION_ID_CLAIM))
                .build();
    }

    /** The subject of one of Contexa's own accounts, named by the account. */
    static ContexaSubject account(Authentication authentication, String accountName, HttpServletRequest request) {
        Map<String, Object> claims = OAuth2AuthenticationSupport.userClaims(authentication);
        String email = authentication.getPrincipal() instanceof UnifiedCustomUserDetails details && details.getAccount() != null
                ? details.getAccount().getEmail()
                : text(claims.get("email"));
        return ContexaSubject.of(accountName, email)
                .authorities(authorities(authentication))
                .authentication(facts(authentication, claims, request))
                .sessionKey(OAuth2AuthenticationSupport.tokenAttribute(authentication, OAuth2AuthenticationSupport.SESSION_ID_CLAIM))
                .build();
    }

    @Nullable
    private static String email(@Nullable String userId, Map<String, Object> claims, List<String> sources,
                                @Nullable BridgeUserEmailProvider provider, Problems problems) {
        for (String source : sources) {
            String email = null;
            if (source.startsWith(CLAIM_SOURCE_PREFIX)) {
                email = text(claims.get(source.substring(CLAIM_SOURCE_PREFIX.length())));
            } else if (PROVIDER_SOURCE.equals(source)) {
                email = provided(userId, provider, problems);
            }
            if (email != null) {
                return email;
            }
        }
        return null;
    }

    @Nullable
    static String provided(@Nullable String userId, @Nullable BridgeUserEmailProvider provider, Problems problems) {
        if (provider == null || userId == null || userId.isBlank()) {
            return null;
        }
        try {
            return text(provider.emailOf(userId.trim()));
        } catch (Exception | LinkageError | StackOverflowError failure) {
            problems.add(SubjectProblem.EMAIL_PROVIDER_FAILED, provider.getClass().getName(), failure);
            return null;
        }
    }

    private static List<String> authorities(Authentication authentication) {
        Collection<? extends GrantedAuthority> granted = authentication.getAuthorities();
        if (granted == null || granted.isEmpty()) {
            return List.of();
        }
        List<String> authorities = new ArrayList<>(granted.size());
        for (GrantedAuthority authority : granted) {
            if (authority != null && authority.getAuthority() != null) {
                authorities.add(authority.getAuthority());
            }
        }
        return authorities;
    }

    @Nullable
    private static ContexaAuthentication facts(Authentication authentication, Map<String, Object> claims,
                                               HttpServletRequest request) {
        if (authentication.getDetails() instanceof ContexaAuthentication stated) {
            return stated;
        }
        List<String> references = strings(claims.get("amr"));
        Instant authenticatedAt = BridgeInstants.parse(claims.get("auth_time"));
        String assurance = text(claims.get("acr"));
        if (!references.isEmpty() || authenticatedAt != null || assurance != null) {
            List<String> methods = AuthenticationMethodReferences.methodsOf(references);
            ContexaAuthentication facts = ContexaAuthentication.of(
                    methods.isEmpty() ? null : AuthenticationMethodReferences.methodName(methods));
            Boolean multiFactor = AuthenticationMethodReferences.multiFactor(references);
            if (multiFactor != null) {
                facts = facts.mfa(multiFactor);
            }
            return facts.authenticatedAt(authenticatedAt).assurance(assurance);
        }
        Object method = request.getAttribute(OfficialContextField.AUTHENTICATION_TYPE.canonicalAttributeKey());
        Boolean verified = bool(request.getAttribute(OfficialContextField.MFA_VERIFIED.canonicalAttributeKey()));
        if (method == null && verified == null) {
            return null;
        }
        ContexaAuthentication facts = ContexaAuthentication.of(text(method));
        return verified != null ? facts.mfa(verified) : facts;
    }

    private static List<String> strings(@Nullable Object value) {
        if (value instanceof Collection<?> values) {
            List<String> texts = new ArrayList<>(values.size());
            for (Object each : values) {
                String text = text(each);
                if (text != null) {
                    texts.add(text);
                }
            }
            return texts;
        }
        String single = text(value);
        return single != null ? List.of(single) : List.of();
    }

    @Nullable
    private static Boolean bool(@Nullable Object value) {
        if (value instanceof Boolean flag) {
            return flag;
        }
        String text = text(value);
        if ("true".equalsIgnoreCase(text)) {
            return Boolean.TRUE;
        }
        if ("false".equalsIgnoreCase(text)) {
            return Boolean.FALSE;
        }
        return null;
    }

    @Nullable
    static String text(@Nullable Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isEmpty() ? null : text;
    }

    /** The problems of one resolution, counted and reported as they are met. */
    interface Problems {

        void add(SubjectProblem problem, @Nullable String detail, @Nullable Throwable failure);

        Set<SubjectProblem> all();
    }
}
