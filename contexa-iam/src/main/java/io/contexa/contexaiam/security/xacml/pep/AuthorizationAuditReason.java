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
package io.contexa.contexaiam.security.xacml.pep;

/**
 * The reason a URL authorization decision is kept with in the audit log (D29). It is a code that names no language, with
 * the AI assessment as JSON when there is one; the security monitor shows it in the language of the screen. The English
 * sentences written before are read as the same reasons, so the records kept from then are shown the same way.
 */
public final class AuthorizationAuditReason {

    /** The URL policies decided, with no AI assessment. */
    public static final String STATIC_RULE = "AUTHZ_STATIC_RULE";
    /** An AI assessment took part; the JSON of the assessment follows after a blank. */
    public static final String AI_ASSESSMENT = "AUTHZ_AI_ASSESSMENT";
    /** An AI assessment took part and could not be written as JSON; its score follows after a blank. */
    public static final String AI_ASSESSMENT_UNREADABLE = "AUTHZ_AI_ASSESSMENT_UNREADABLE";

    static final String STATIC_RULE_KEY = "admin.security.monitor.reason.static.rule";
    static final String AI_ASSESSMENT_KEY = "admin.security.monitor.reason.ai.assessment";
    static final String AI_ASSESSMENT_UNREADABLE_KEY = "admin.security.monitor.reason.ai.assessment.unreadable";

    private static final String LEGACY_STATIC_RULE = "Static rule matching";
    private static final String LEGACY_AI_ASSESSMENT = "AI assessment result: ";
    private static final String LEGACY_AI_ASSESSMENT_UNREADABLE = "AI assessment result serialization failed. Score: ";

    private AuthorizationAuditReason() {
    }

    static String aiAssessment(String assessmentJson) {
        return AI_ASSESSMENT + ' ' + assessmentJson;
    }

    static String aiAssessmentUnreadable(double score) {
        return AI_ASSESSMENT_UNREADABLE + ' ' + score;
    }

    /**
     * The message key and its argument a stored reason is shown with, or {@code null} for a reason written by anything
     * else, which is shown as it was stored.
     */
    public static Display describe(String stored) {
        if (stored == null) {
            return null;
        }
        if (STATIC_RULE.equals(stored) || LEGACY_STATIC_RULE.equals(stored)) {
            return new Display(STATIC_RULE_KEY, "");
        }
        // The longer code first: it starts with the shorter one.
        String unreadable = after(stored, AI_ASSESSMENT_UNREADABLE + ' ', LEGACY_AI_ASSESSMENT_UNREADABLE);
        if (unreadable != null) {
            return new Display(AI_ASSESSMENT_UNREADABLE_KEY, unreadable);
        }
        String assessment = after(stored, AI_ASSESSMENT + ' ', LEGACY_AI_ASSESSMENT);
        if (assessment != null) {
            return new Display(AI_ASSESSMENT_KEY, assessment);
        }
        return null;
    }

    private static String after(String stored, String code, String legacy) {
        if (stored.startsWith(code)) {
            return stored.substring(code.length());
        }
        if (stored.startsWith(legacy)) {
            return stored.substring(legacy.length());
        }
        return null;
    }

    /** A reason as a message key of the security monitor and the value it is shown with. */
    public record Display(String key, String argument) {
    }
}
