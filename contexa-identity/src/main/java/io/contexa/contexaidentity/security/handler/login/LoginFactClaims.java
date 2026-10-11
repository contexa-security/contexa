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

import io.contexa.contexacommon.security.bridge.OAuth2AuthenticationSupport;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

/**
 * The login facts as the standard token claims {@code auth_time}, {@code amr}, {@code acr} and {@code sid} (OpenID
 * Connect), so that a token state carries the same login as a session, and its requests one session (the login). The
 * facts no standard claim names (the principal type, and a passed Zero Trust challenge, which the login's methods do
 * not state) use the keys the bridge reads them by. They travel to the token engine as text and are written as claims
 * of their types.
 */
public final class LoginFactClaims {

    public static final String AUTH_TIME = "auth_time";
    public static final String AMR = "amr";
    public static final String ACR = "acr";
    public static final String SID = OAuth2AuthenticationSupport.SESSION_ID_CLAIM;
    public static final String PRINCIPAL_TYPE = "principalType";
    public static final String MFA_COMPLETED = "mfaCompleted";
    public static final String CHALLENGE_VERIFIED_AT = "challengeVerifiedAt";
    public static final List<String> NAMES = List.of(AUTH_TIME, AMR, ACR, SID, PRINCIPAL_TYPE, MFA_COMPLETED,
            CHALLENGE_VERIFIED_AT);

    private LoginFactClaims() {
    }

    /** The login facts recorded on an authentication, as text by claim name; empty when it carries none. */
    public static Map<String, String> of(@Nullable Authentication authentication) {
        Map<String, String> facts = new LinkedHashMap<>();
        if (authentication == null || !(authentication.getDetails() instanceof LoginFactsDetails details)) {
            return facts;
        }
        // A challenge passed on a session whose login left no facts has no login time.
        if (details.getAuthenticationTime() != null) {
            facts.put(AUTH_TIME, String.valueOf(details.getAuthenticationTime().getEpochSecond()));
        }
        if (!details.getAmr().isEmpty()) {
            facts.put(AMR, String.join(" ", details.getAmr()));
        }
        if (details.getAuthenticationAssurance() != null) {
            facts.put(ACR, details.getAuthenticationAssurance());
        }
        facts.put(SID, details.getSignInId());
        if (details.getPrincipalType() != null) {
            facts.put(PRINCIPAL_TYPE, details.getPrincipalType());
        }
        if (details.getChallengeVerifiedAt() != null) {
            facts.put(MFA_COMPLETED, Boolean.TRUE.toString());
            facts.put(CHALLENGE_VERIFIED_AT, details.getChallengeVerifiedAt().toString());
        }
        return facts;
    }

    /**
     * Writes the facts as claims: {@code auth_time} as a {@link Date} (the type the token engine itself writes it in;
     * the encoder puts it in the token in epoch seconds, and the stored authorization can read it back), {@code amr}
     * as an {@link ArrayList} (an unmodifiable list does not read back from the stored authorization), {@code acr},
     * {@code sid} and the principal type as text, {@code mfaCompleted} as a boolean, {@code challengeVerifiedAt} as
     * ISO-8601 text (the form a session states it in).
     */
    public static void writeClaims(Map<String, ?> facts, BiConsumer<String, Object> claim) {
        Object authTime = facts.get(AUTH_TIME);
        if (authTime != null && StringUtils.hasText(authTime.toString())) {
            try {
                claim.accept(AUTH_TIME, Date.from(Instant.ofEpochSecond(Long.parseLong(authTime.toString().trim()))));
            } catch (NumberFormatException ignored) {
                // A value that is not epoch seconds is not an authentication time and is not written.
            }
        }
        Object amr = facts.get(AMR);
        if (amr != null && StringUtils.hasText(amr.toString())) {
            claim.accept(AMR, new ArrayList<>(Arrays.asList(amr.toString().trim().split("\\s+"))));
        }
        Object acr = facts.get(ACR);
        if (acr != null && StringUtils.hasText(acr.toString())) {
            claim.accept(ACR, acr.toString().trim());
        }
        Object sid = facts.get(SID);
        if (sid != null && StringUtils.hasText(sid.toString())) {
            claim.accept(SID, sid.toString().trim());
        }
        Object principalType = facts.get(PRINCIPAL_TYPE);
        if (principalType != null && StringUtils.hasText(principalType.toString())) {
            claim.accept(PRINCIPAL_TYPE, principalType.toString().trim());
        }
        Object mfaCompleted = facts.get(MFA_COMPLETED);
        if (mfaCompleted != null && Boolean.TRUE.toString().equalsIgnoreCase(mfaCompleted.toString().trim())) {
            claim.accept(MFA_COMPLETED, Boolean.TRUE);
        }
        Object challengeVerifiedAt = facts.get(CHALLENGE_VERIFIED_AT);
        if (challengeVerifiedAt != null && StringUtils.hasText(challengeVerifiedAt.toString())) {
            try {
                claim.accept(CHALLENGE_VERIFIED_AT, Instant.parse(challengeVerifiedAt.toString().trim()).toString());
            } catch (DateTimeParseException ignored) {
                // A value that is not an instant is not a challenge time and is not written.
            }
        }
    }
}
