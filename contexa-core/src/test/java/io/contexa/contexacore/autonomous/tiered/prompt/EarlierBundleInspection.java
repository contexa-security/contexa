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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspector;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plan 6-2 (decision D7): a package drawn with a bundle this build no longer ships (the v20 and v21 bundles) is not read
 * again. Each check that reads the dictionary prompt records it unread, with the bundle it names and why, and finds
 * nothing in it; the real v20 packages the showcase engine sealed are such packages.
 */
final class EarlierBundleInspection {

    /** Where a package names the bundle its prompt was drawn with. */
    static final String SEALED_BUNDLE = "executionMetadata.governanceDescriptor.promptBundleVersion";
    /** The end of the reason a check gives for a package it does not read again. */
    static final String NOT_READ_AGAIN = "cannot be inspected again (decision D7)";

    private EarlierBundleInspection() {
    }

    /**
     * Inspects each package and requires every dictionary check of the inspector to record it unread under D7 without
     * any match or mismatch; returns how many packages were inspected.
     */
    static int assertNotReadAgain(PromptInspector inspector, List<SealedEvidencePackage> packages) {
        assertThat(packages).isNotEmpty();
        List<String> dictionaryChecks = inspector.checks().stream().filter(PromptInspectionCheck::dictionaryPromptOnly)
                .map(PromptInspectionCheck::code).toList();
        assertThat(dictionaryChecks).isNotEmpty();
        for (SealedEvidencePackage sealed : packages) {
            PromptInspectionResult result = inspector.inspect(sealed);
            assertThat(result.layoutVersion()).as(sealed.getPackageId())
                    .isIn(PromptInspector.V20_LAYOUT, PromptInspector.V21_LAYOUT);
            List<PromptInspectionCheckResult> unread = result.checks().stream()
                    .filter(check -> dictionaryChecks.contains(check.checkCode())).toList();
            assertThat(unread).as(sealed.getPackageId()).hasSameSizeAs(dictionaryChecks);
            for (PromptInspectionCheckResult check : unread) {
                assertThat(check.matched()).as(sealed.getPackageId() + " " + check.checkCode()).isZero();
                assertThat(check.mismatched()).as(sealed.getPackageId() + " " + check.checkCode()).isZero();
                assertThat(check.findings()).as(sealed.getPackageId() + " " + check.checkCode()).singleElement()
                        .satisfies(finding -> {
                            assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
                            assertThat(finding.sourceRef()).isEqualTo(SEALED_BUNDLE);
                            assertThat(finding.actual()).isNotBlank();
                            assertThat(finding.reason()).endsWith(NOT_READ_AGAIN);
                        });
            }
        }
        return packages.size();
    }
}
