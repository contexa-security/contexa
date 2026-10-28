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
package io.contexa.contexacore.autonomous.context.support;

import io.contexa.contexacommon.annotation.ResourceImportance;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** RL-14: one reading of a resource's importance for every part of the engine that tells sensitive from the rest. */
class ResourceImportanceResolverTest {

    /** IM-02: a resource declared sensitive stays sensitive whatever the host states for the request. */
    @Test
    void aDeclaredSensitiveResourceStaysSensitiveWhateverTheHostStates() {
        assertThat(ResourceImportanceResolver.resolve(ResourceImportance.SENSITIVE, "PUBLIC"))
                .isEqualTo(ResourceImportance.SENSITIVE);
        assertThat(ResourceImportanceResolver.resolve(ResourceImportance.SENSITIVE, "INTERNAL", "LOW"))
                .isEqualTo(ResourceImportance.SENSITIVE);
        assertThat(ResourceImportanceResolver.resolve(ResourceImportance.SENSITIVE))
                .isEqualTo(ResourceImportance.SENSITIVE);
    }

    /** IM-03, IM-04: the host may raise a resource declared non-sensitive for one request, never lower it. */
    @Test
    void theHostCanRaiseADeclaredNonSensitiveResourceButNotLowerASensitiveOne() {
        assertThat(ResourceImportanceResolver.resolve(ResourceImportance.NON_SENSITIVE, "RESTRICTED"))
                .isEqualTo(ResourceImportance.SENSITIVE);
        assertThat(ResourceImportanceResolver.resolve(ResourceImportance.NON_SENSITIVE, null, "CONFIDENTIAL"))
                .isEqualTo(ResourceImportance.SENSITIVE);
        assertThat(ResourceImportanceResolver.resolve(ResourceImportance.NON_SENSITIVE, "CRITICAL"))
                .isEqualTo(ResourceImportance.SENSITIVE);
    }

    /** IM-05, IM-06: a declared non-sensitive resource with no or a lower host value is non-sensitive. */
    @Test
    void aDeclaredNonSensitiveResourceStaysNonSensitiveWithNoOrALowerHostValue() {
        assertThat(ResourceImportanceResolver.resolve(ResourceImportance.NON_SENSITIVE))
                .isEqualTo(ResourceImportance.NON_SENSITIVE);
        assertThat(ResourceImportanceResolver.resolve(ResourceImportance.NON_SENSITIVE, (Object) null))
                .isEqualTo(ResourceImportance.NON_SENSITIVE);
        assertThat(ResourceImportanceResolver.resolve(ResourceImportance.NON_SENSITIVE, "INTERNAL"))
                .isEqualTo(ResourceImportance.NON_SENSITIVE);
        assertThat(ResourceImportanceResolver.resolve(ResourceImportance.NON_SENSITIVE, "PUBLIC", "unknown-word"))
                .isEqualTo(ResourceImportance.NON_SENSITIVE);
    }

    /**
     * IM-07, IM-08: a resource that declares nothing reads as before: sensitive when a word classifies as sensitive
     * or critical, else unspecified. A word such as PUBLIC does not make it a declared non-sensitive resource.
     */
    @Test
    void anUndeclaredResourceReadsAsBeforeFromTheWordsAndNeverBecomesNonSensitiveByAWord() {
        assertThat(ResourceImportanceResolver.resolve(ResourceImportance.UNSPECIFIED))
                .isEqualTo(ResourceImportance.UNSPECIFIED);
        assertThat(ResourceImportanceResolver.resolve(null)).isEqualTo(ResourceImportance.UNSPECIFIED);
        assertThat(ResourceImportanceResolver.resolve(ResourceImportance.UNSPECIFIED, "CRITICAL"))
                .isEqualTo(ResourceImportance.SENSITIVE);
        assertThat(ResourceImportanceResolver.resolve(ResourceImportance.UNSPECIFIED, "CONFIDENTIAL"))
                .isEqualTo(ResourceImportance.SENSITIVE);
        assertThat(ResourceImportanceResolver.resolve(ResourceImportance.UNSPECIFIED, "PUBLIC"))
                .isEqualTo(ResourceImportance.UNSPECIFIED);
        assertThat(ResourceImportanceResolver.resolve(ResourceImportance.UNSPECIFIED, "INTERNAL"))
                .isEqualTo(ResourceImportance.UNSPECIFIED);
    }

    /** The request's payload carries the declared importance under its own key beside the two sensitivity words. */
    @Test
    void thePayloadFormReadsTheDeclaredImportanceAndBothSensitivityWords() {
        assertThat(ResourceImportanceResolver.of(Map.of("resourceImportance", "SENSITIVE", "resourceSensitivity", "PUBLIC")))
                .isEqualTo(ResourceImportance.SENSITIVE);
        assertThat(ResourceImportanceResolver.of(Map.of("resourceImportance", "NON_SENSITIVE",
                "resourceSensitivity", "RESTRICTED"))).isEqualTo(ResourceImportance.SENSITIVE);
        assertThat(ResourceImportanceResolver.of(Map.of("resourceImportance", "NON_SENSITIVE",
                "sensitivity", "HIGH"))).isEqualTo(ResourceImportance.SENSITIVE);
        assertThat(ResourceImportanceResolver.of(Map.of("resourceImportance", "NON_SENSITIVE")))
                .isEqualTo(ResourceImportance.NON_SENSITIVE);
        assertThat(ResourceImportanceResolver.of(Map.of("resourceSensitivity", "RESTRICTED")))
                .isEqualTo(ResourceImportance.SENSITIVE);
        assertThat(ResourceImportanceResolver.of(Map.of())).isEqualTo(ResourceImportance.UNSPECIFIED);
        assertThat(ResourceImportanceResolver.of(null)).isEqualTo(ResourceImportance.UNSPECIFIED);
    }

    @Test
    void anUnknownDeclaredValueIsReadAsUnspecifiedAndALowerCaseOneIsRead() {
        Map<String, Object> payload = new HashMap<>();
        payload.put("resourceImportance", "no-such-importance");
        assertThat(ResourceImportanceResolver.of(payload)).isEqualTo(ResourceImportance.UNSPECIFIED);
        payload.put("resourceImportance", "sensitive");
        assertThat(ResourceImportanceResolver.of(payload)).isEqualTo(ResourceImportance.SENSITIVE);
        payload.put("resourceImportance", 7);
        assertThat(ResourceImportanceResolver.of(payload)).isEqualTo(ResourceImportance.UNSPECIFIED);
    }

    @Test
    void sensitiveIsTheYesNoFormOfTheSameReading() {
        assertThat(ResourceImportanceResolver.sensitive(Map.of("resourceImportance", "SENSITIVE"))).isTrue();
        assertThat(ResourceImportanceResolver.sensitive(Map.of("resourceImportance", "NON_SENSITIVE"))).isFalse();
        assertThat(ResourceImportanceResolver.sensitive(Map.of())).isFalse();
        assertThat(ResourceImportanceResolver.sensitive(null)).isFalse();
    }

    /** Only a resource the host declared non-sensitive may be a candidate for a pass before the verdict (RL-12). */
    @Test
    void onlyADeclaredNonSensitiveResourceIsAnExplicitNonSensitiveOne() {
        assertThat(ResourceImportanceResolver.explicitlyNonSensitive(Map.of("resourceImportance", "NON_SENSITIVE")))
                .isTrue();
        assertThat(ResourceImportanceResolver.explicitlyNonSensitive(Map.of("resourceImportance", "NON_SENSITIVE",
                "resourceSensitivity", "RESTRICTED"))).isFalse();
        assertThat(ResourceImportanceResolver.explicitlyNonSensitive(Map.of("resourceSensitivity", "PUBLIC"))).isFalse();
        assertThat(ResourceImportanceResolver.explicitlyNonSensitive(Map.of())).isFalse();
        assertThat(ResourceImportanceResolver.explicitlyNonSensitive(Map.of("resourceImportance", "SENSITIVE"))).isFalse();
    }
}
