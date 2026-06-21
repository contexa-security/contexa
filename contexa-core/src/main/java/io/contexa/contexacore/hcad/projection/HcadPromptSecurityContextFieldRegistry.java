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

import io.contexa.contexacommon.hcad.official.OfficialContextField;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class HcadPromptSecurityContextFieldRegistry {

    public static final String VERSION = "hcad-prompt-security-context-v1";

    private static final Map<String, HcadPromptSecurityContextFieldContract> CONTRACTS = buildContracts();

    private HcadPromptSecurityContextFieldRegistry() {
    }

    public static String version() {
        return VERSION;
    }

    public static HcadPromptSecurityContextFieldContract contract(String hcadField) {
        return hcadField == null ? null : CONTRACTS.get(hcadField);
    }

    public static boolean isScoringAllowed(String hcadField, HcadTrustedSource source) {
        HcadPromptSecurityContextFieldContract contract = contract(hcadField);
        return contract != null && contract.allowsScoringFrom(source);
    }

    public static Map<String, Map<String, Object>> snapshot(Map<String, HcadFieldProvenance> provenance) {
        Map<String, Map<String, Object>> snapshot = new LinkedHashMap<>();
        if (provenance == null || provenance.isEmpty()) {
            CONTRACTS.forEach((field, contract) -> snapshot.put(field, contract.toSnapshot()));
            return snapshot;
        }
        provenance.forEach((field, fieldProvenance) -> {
            HcadPromptSecurityContextFieldContract contract = contract(field);
            Map<String, Object> contractSnapshot = contract == null
                    ? excludedUnknown(field).toSnapshot()
                    : contract.toSnapshot();
            if (fieldProvenance != null) {
                contractSnapshot.put("actualSource", fieldProvenance.source().name());
                contractSnapshot.put("present", fieldProvenance.present());
            }
            snapshot.put(field, contractSnapshot);
        });
        return snapshot;
    }

    public static Map<String, Object> scoringSnapshot(Map<String, HcadFieldProvenance> provenance) {
        Map<String, Object> snapshot = new LinkedHashMap<>();
        snapshot.put("contractVersion", VERSION);
        snapshot.put("fields", snapshot(provenance));
        snapshot.put("excludedFields", excludedFields(provenance));
        return snapshot;
    }

    public static List<Map<String, Object>> excludedFields(Map<String, HcadFieldProvenance> provenance) {
        if (provenance == null || provenance.isEmpty()) {
            return CONTRACTS.values().stream()
                    .filter(contract -> !contract.scoringAllowed())
                    .map(HcadPromptSecurityContextFieldContract::toSnapshot)
                    .toList();
        }
        return provenance.keySet().stream()
                .map(field -> {
                    HcadPromptSecurityContextFieldContract contract = contract(field);
                    return contract == null ? excludedUnknown(field) : contract;
                })
                .filter(contract -> !contract.scoringAllowed())
                .map(HcadPromptSecurityContextFieldContract::toSnapshot)
                .toList();
    }

    private static Map<String, HcadPromptSecurityContextFieldContract> buildContracts() {
        Map<String, HcadPromptSecurityContextFieldContract> contracts = new LinkedHashMap<>();
        register(contracts, observe("userId", "UserId", null, "identity.userId",
                List.of(HcadTrustedSource.BRIDGE_VERIFIED, HcadTrustedSource.TRUSTED_SERVER),
                "none", "TrustedHcadContextProjectionFactory"));
        register(contracts, observe("tenantId", "TenantId", OfficialContextField.TENANT_ID, "identity.tenantId",
                List.of(HcadTrustedSource.BRIDGE_VERIFIED),
                "none", "TrustedHcadContextProjectionFactory"));
        register(contracts, observe("organizationId", "OrganizationId", OfficialContextField.ORGANIZATION_ID,
                "identity.organizationId", List.of(HcadTrustedSource.BRIDGE_VERIFIED),
                "none", "TrustedHcadContextProjectionFactory"));
        register(contracts, nonScoring("sessionId", "SessionId", null, "session.sessionId",
                List.of(HcadTrustedSource.TRUSTED_SERVER, HcadTrustedSource.BRIDGE_VERIFIED),
                HcadPromptSecurityContextFieldUse.DEDUP_ONLY,
                "none", "TrustedHcadContextProjectionFactory",
                "Session identity is used for actor-window coalescing, not risk scoring."));
        register(contracts, nonScoring("contextBindingHash", "ContextBindingHash", null, "hcad.contextBindingHash",
                List.of(HcadTrustedSource.TRUSTED_SERVER),
                HcadPromptSecurityContextFieldUse.DEDUP_ONLY,
                "SessionFingerprintUtil.generateContextBindingHash",
                "TrustedHcadContextProjectionFactory",
                "HCAD internal dedup key; it is not an LLM prompt standard risk field."));
        register(contracts, observe("method", "HttpMethod", null, "resource.httpMethod",
                List.of(HcadTrustedSource.TRUSTED_SERVER),
                "none", "TrustedHcadContextProjectionFactory"));
        register(contracts, scoring("normalizedPath", "RequestPath/CurrentPathFamily", null,
                "resource.requestPath", List.of(HcadTrustedSource.TRUSTED_SERVER),
                HcadPromptSecurityContextFieldUse.CORROBORATING,
                "HcadRequestPathUtils.normalizedPath + SecuritySemanticNormalizer.normalizePathFamily",
                "TrustedHcadContextProjectionFactory"));
        register(contracts, scoring("clientIp", "ClientIp/IpBand", OfficialContextField.IP_BAND,
                "location.ipBand", List.of(HcadTrustedSource.TRUSTED_SERVER),
                HcadPromptSecurityContextFieldUse.CORROBORATING,
                "SecuritySemanticNormalizer.normalizeNetwork",
                "TrustedHcadContextProjectionFactory"));
        register(contracts, scoring("authenticationMethod", "AuthenticationType", OfficialContextField.AUTHENTICATION_TYPE,
                "session.authenticationType",
                List.of(HcadTrustedSource.BRIDGE_VERIFIED, HcadTrustedSource.TRUSTED_SERVER),
                HcadPromptSecurityContextFieldUse.ANCHOR,
                "SecuritySemanticNormalizer.normalizeAuthenticationType",
                "TrustedHcadContextProjectionFactory"));
        register(contracts, scoring("authenticationAssurance", "AuthenticationAssurance", null,
                "session.authenticationAssurance", List.of(HcadTrustedSource.BRIDGE_VERIFIED),
                HcadPromptSecurityContextFieldUse.CORROBORATING,
                "lowercase-token", "TrustedHcadContextProjectionFactory"));
        register(contracts, scoring("mfaVerified", "MfaVerified", OfficialContextField.MFA_VERIFIED,
                "session.mfaVerified",
                List.of(HcadTrustedSource.BRIDGE_VERIFIED, HcadTrustedSource.TRUSTED_SERVER),
                HcadPromptSecurityContextFieldUse.ANCHOR,
                "boolean", "TrustedHcadContextProjectionFactory"));
        register(contracts, scoring("mfaFreshnessSeconds", "MfaFreshnessSeconds", null,
                "session.mfaFreshnessSeconds", List.of(HcadTrustedSource.BRIDGE_VERIFIED),
                HcadPromptSecurityContextFieldUse.ANCHOR,
                "duration-seconds", "TrustedHcadContextProjectionFactory"));
        register(contracts, observe("authorizationPolicyId", "PolicyId", null,
                "authorization.policyId", List.of(HcadTrustedSource.BRIDGE_VERIFIED),
                "none", "TrustedHcadContextProjectionFactory"));
        register(contracts, scoring("authorizationPrivileged", "PrivilegedFlow", null,
                "authorization.privilegedFlow", List.of(HcadTrustedSource.BRIDGE_VERIFIED),
                HcadPromptSecurityContextFieldUse.ANCHOR,
                "boolean", "TrustedHcadContextProjectionFactory"));
        register(contracts, scoring("verificationRequired", "FrictionRequired", null,
                "friction.verificationRequired", List.of(HcadTrustedSource.BRIDGE_VERIFIED),
                HcadPromptSecurityContextFieldUse.ANCHOR,
                "boolean", "TrustedHcadContextProjectionFactory"));
        register(contracts, scoring("recentPermissionChanges", "RecentPermissionChanges", null,
                "authorization.recentPermissionChanges", List.of(HcadTrustedSource.STORE_DERIVED),
                HcadPromptSecurityContextFieldUse.ANCHOR,
                "none", "SecurityContextDataStore"));
        register(contracts, scoring("failedLoginBurst", "FailedLoginAttempts", OfficialContextField.FAILED_LOGIN_ATTEMPTS,
                "session.failedLoginAttempts", List.of(HcadTrustedSource.STORE_DERIVED),
                HcadPromptSecurityContextFieldUse.ANCHOR,
                "count", "SecurityContextDataStore"));
        register(contracts, scoring("requestBurst", "RecentRequestCount", OfficialContextField.RECENT_REQUEST_COUNT,
                "session.recentRequestCount", List.of(HcadTrustedSource.STORE_DERIVED),
                HcadPromptSecurityContextFieldUse.CORROBORATING,
                "rolling-window-count", "HCADDataStore"));
        register(contracts, scoring("rapidSequence", "BurstPattern", null,
                "session.burstPattern", List.of(HcadTrustedSource.STORE_DERIVED),
                HcadPromptSecurityContextFieldUse.CORROBORATING,
                "duration-threshold", "SecurityContextDataStore"));
        register(contracts, scoring("previousPath", "PreviousPath", null,
                "session.previousPath", List.of(HcadTrustedSource.STORE_DERIVED),
                HcadPromptSecurityContextFieldUse.CORROBORATING,
                "HcadRequestPathUtils.normalizedPath + SecuritySemanticNormalizer.normalizePathFamily",
                "SecurityContextDataStore"));
        register(contracts, scoring("impossibleTravel", "ImpossibleTravel", OfficialContextField.IMPOSSIBLE_TRAVEL,
                "intent.impossibleTravel", List.of(HcadTrustedSource.STORE_DERIVED),
                HcadPromptSecurityContextFieldUse.ANCHOR,
                "boolean", "HCADDataStore"));
        register(contracts, nonScoring("baselineConfidence", "BaselineConfidence", null,
                "workProfile.baselineConfidence", List.of(HcadTrustedSource.STORE_DERIVED),
                HcadPromptSecurityContextFieldUse.OBSERVE_ONLY,
                "decimal", "HCADDataStore",
                "Baseline confidence is retained for monitoring only; it is not a prompt standard risk field."));
        register(contracts, nonScoring("baselineEstablished", "BaselineEstablished", null,
                "workProfile.baselineEstablished", List.of(HcadTrustedSource.STORE_DERIVED),
                HcadPromptSecurityContextFieldUse.OBSERVE_ONLY,
                "boolean", "HCADDataStore",
                "Baseline availability is context for the operator, not a standalone trigger."));
        register(contracts, scoring("baselineComparison", "WorkProfileEvidenceState", null,
                "workProfile.personalBaselineComparison", List.of(HcadTrustedSource.STORE_DERIVED),
                HcadPromptSecurityContextFieldUse.CORROBORATING,
                "contract-field-comparison", "BaselineDataStore"));
        return Map.copyOf(contracts);
    }

    private static void register(
            Map<String, HcadPromptSecurityContextFieldContract> contracts,
            HcadPromptSecurityContextFieldContract contract) {
        contracts.put(contract.hcadField(), contract);
    }

    private static HcadPromptSecurityContextFieldContract scoring(
            String hcadField,
            String promptLabel,
            OfficialContextField officialField,
            String canonicalPath,
            List<HcadTrustedSource> allowedSources,
            HcadPromptSecurityContextFieldUse use,
            String normalizer,
            String owner) {
        return new HcadPromptSecurityContextFieldContract(
                hcadField,
                promptLabel,
                officialField == null ? null : officialField.metadataKey(),
                canonicalPath,
                allowedSources,
                use,
                normalizer,
                owner,
                true,
                "");
    }

    private static HcadPromptSecurityContextFieldContract observe(
            String hcadField,
            String promptLabel,
            OfficialContextField officialField,
            String canonicalPath,
            List<HcadTrustedSource> allowedSources,
            String normalizer,
            String owner) {
        return nonScoring(
                hcadField,
                promptLabel,
                officialField,
                canonicalPath,
                allowedSources,
                HcadPromptSecurityContextFieldUse.OBSERVE_ONLY,
                normalizer,
                owner,
                "Identity and scope fields explain the event but do not independently score risk.");
    }

    private static HcadPromptSecurityContextFieldContract nonScoring(
            String hcadField,
            String promptLabel,
            OfficialContextField officialField,
            String canonicalPath,
            List<HcadTrustedSource> allowedSources,
            HcadPromptSecurityContextFieldUse use,
            String normalizer,
            String owner,
            String exclusionReason) {
        return new HcadPromptSecurityContextFieldContract(
                hcadField,
                promptLabel,
                officialField == null ? null : officialField.metadataKey(),
                canonicalPath,
                allowedSources,
                use,
                normalizer,
                owner,
                false,
                exclusionReason);
    }

    private static HcadPromptSecurityContextFieldContract excludedUnknown(String hcadField) {
        return new HcadPromptSecurityContextFieldContract(
                hcadField,
                null,
                null,
                null,
                List.of(),
                HcadPromptSecurityContextFieldUse.EXCLUDED,
                "",
                "",
                false,
                "Field is not registered in the HCAD prompt security context contract.");
    }
}
