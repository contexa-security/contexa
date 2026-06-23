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
package io.contexa.contexacore.hcad.promotion;

import java.util.List;

public enum HcadPreProtectablePromotionSignal {
    IMPOSSIBLE_TRAVEL(true, 45, List.of("impossibleTravel")),
    FAILED_LOGIN_BURST(true, 50, List.of("failedLoginBurst")),
    AUTH_CONTEXT_INCONSISTENT(true, 40, List.of("authenticationMethod", "mfaVerified")),
    RECENT_PERMISSION_CHANGE(true, 35, List.of("recentPermissionChanges")),
    PRIVILEGED_AUTHORIZATION(true, 35, List.of("authorizationPrivileged")),
    FRESH_MFA_REQUIRED(true, 35, List.of("verificationRequired", "mfaVerified", "mfaFreshnessSeconds")),
    REQUEST_BURST(false, 10, List.of("requestBurst")),
    RAPID_SEQUENCE(false, 10, List.of("rapidSequence")),
    PREVIOUS_PATH_JUMP(false, 10, List.of("previousPath", "normalizedPath")),
    LOW_AUTH_ASSURANCE(false, 15, List.of("authenticationAssurance")),
    BASELINE_MATERIAL_MISMATCH(false, 20, List.of("baselineComparison")),
    SEMANTIC_EVIDENCE_MISMATCH(false, 15, List.of("semanticEvidence")),
    SEMANTIC_RISK_SIMILARITY(false, 20, List.of("semanticEvidence"));

    private final boolean anchor;
    private final int weight;
    private final List<String> requiredContractFields;

    HcadPreProtectablePromotionSignal(boolean anchor, int weight, List<String> requiredContractFields) {
        this.anchor = anchor;
        this.weight = weight;
        this.requiredContractFields = List.copyOf(requiredContractFields);
    }

    public boolean isAnchor() {
        return anchor;
    }

    public int weight() {
        return weight;
    }

    public List<String> requiredContractFields() {
        return requiredContractFields;
    }
}
