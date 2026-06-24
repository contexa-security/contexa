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
package io.contexa.contexacore.hcad.projection;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public record TrustedHcadContextProjection(
        String userId,
        String tenantId,
        String organizationId,
        String sessionId,
        String contextBindingHash,
        String method,
        String normalizedPath,
        String clientIp,
        String authenticationMethod,
        String authenticationAssurance,
        Boolean mfaVerified,
        Long mfaFreshnessSeconds,
        String authorizationPolicyId,
        Boolean authorizationPrivileged,
        Boolean verificationRequired,
        List<String> recentPermissionChanges,
        Integer failedLoginBurst,
        Integer requestBurst,
        Boolean rapidSequence,
        String previousPath,
        Boolean impossibleTravel,
        Double baselineConfidence,
        Boolean baselineEstablished,
        HcadBaselineComparison baselineComparison,
        String promptContextContractVersion,
        Map<String, Map<String, Object>> promptContextFieldContracts,
        Map<String, HcadFieldProvenance> provenance,
        Map<String, Object> ignoredInputs
) {

    public TrustedHcadContextProjection {
        recentPermissionChanges = recentPermissionChanges == null ? List.of() : List.copyOf(recentPermissionChanges);
        baselineComparison = baselineComparison == null ? HcadBaselineComparison.unavailable(0) : baselineComparison;
        promptContextContractVersion = promptContextContractVersion == null
                ? HcadPromptSecurityContextFieldRegistry.version()
                : promptContextContractVersion;
        promptContextFieldContracts = promptContextFieldContracts == null
                ? Map.of()
                : Collections.unmodifiableMap(new LinkedHashMap<>(promptContextFieldContracts));
        provenance = provenance == null
                ? Map.of()
                : Collections.unmodifiableMap(new LinkedHashMap<>(provenance));
        ignoredInputs = ignoredInputs == null
                ? Map.of()
                : Collections.unmodifiableMap(new LinkedHashMap<>(ignoredInputs));
    }

    public HcadTrustedSource sourceOf(String fieldName) {
        HcadFieldProvenance fieldProvenance = provenance.get(fieldName);
        return fieldProvenance == null ? HcadTrustedSource.ABSENT : fieldProvenance.source();
    }

    public boolean hasTrustedSource(String fieldName, HcadTrustedSource... allowedSources) {
        HcadTrustedSource actual = sourceOf(fieldName);
        if (allowedSources == null || allowedSources.length == 0) {
            return actual == HcadTrustedSource.TRUSTED_SERVER
                    || actual == HcadTrustedSource.BRIDGE_VERIFIED
                    || actual == HcadTrustedSource.STORE_DERIVED
                    || actual == HcadTrustedSource.CACHE_DERIVED;
        }
        for (HcadTrustedSource allowedSource : allowedSources) {
            if (actual == allowedSource) {
                return true;
            }
        }
        return false;
    }

    public boolean hasScorableTrustedSource(String fieldName, HcadTrustedSource... allowedSources) {
        HcadTrustedSource actual = sourceOf(fieldName);
        if (!HcadPromptSecurityContextFieldRegistry.isScoringAllowed(fieldName, actual)) {
            return false;
        }
        if (allowedSources == null || allowedSources.length == 0) {
            return true;
        }
        for (HcadTrustedSource allowedSource : allowedSources) {
            if (actual == allowedSource) {
                return true;
            }
        }
        return false;
    }
}
