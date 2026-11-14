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
package io.contexa.contexacore.verification.inspection;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;

import java.util.Map;

/**
 * Test support: one check over one sealed package, as the inspector runs it on a package drawn in this build's form,
 * for checks of a layout whose bundles the catalog does not hold yet.
 */
public final class InspectionCheckRunner {

    private InspectionCheckRunner() {
    }

    public static PromptInspectionCheckResult run(PromptInspectionCheck check, SealedEvidencePackage sealed,
                                                  String layout, Map<String, Object> executionMetadata,
                                                  CanonicalSecurityContext context) {
        PromptInspectionSubject subject = new PromptInspectionSubject(sealed, layout,
                InspectedPrompt.parse(sealed.getUserPromptText()), executionMetadata, context);
        PromptInspectionTally tally = new PromptInspectionTally(check.code(), subject);
        check.inspect(tally);
        return tally.result();
    }
}
