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
package io.contexa.contexacore.hcad.semantic;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.hcad.trigger.HcadRequestPathUtils;
import io.contexa.contexacore.properties.HcadProperties;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

@Slf4j
public class HcadSemanticEvidenceRefreshService {

    private final Supplier<HcadSemanticEvidenceCache> cacheSupplier;
    private final Supplier<HcadSemanticEvidenceWarmupService> warmupServiceSupplier;
    private final HcadProperties hcadProperties;

    public HcadSemanticEvidenceRefreshService(
            Supplier<HcadSemanticEvidenceCache> cacheSupplier,
            Supplier<HcadSemanticEvidenceWarmupService> warmupServiceSupplier,
            HcadProperties hcadProperties) {
        this.cacheSupplier = cacheSupplier == null ? () -> null : cacheSupplier;
        this.warmupServiceSupplier = warmupServiceSupplier == null ? () -> null : warmupServiceSupplier;
        this.hcadProperties = hcadProperties;
    }

    public void refreshAfterDecision(SecurityEvent event, Map<String, Object> metadata) {
        refreshAfterDecision(event, metadata, "ALLOW");
    }

    public void refreshAfterDecision(SecurityEvent event, Map<String, Object> metadata, String learningAction) {
        if (!enabled()) {
            return;
        }
        HcadSemanticEvidenceCache cache = cacheSupplier.get();
        HcadSemanticEvidenceWarmupService warmupService = warmupServiceSupplier.get();
        if (cache == null
                || cache.provider() == HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider.DISABLED
                || warmupService == null) {
            return;
        }
        for (HcadSemanticEvidenceKey key : decisionEvidenceKeys(event, metadata, learningAction)) {
            try {
                cache.invalidate(key);
                warmupService.requestWarmup(new HcadSemanticEvidenceWarmupRequest(null, key), cache);
            } catch (RuntimeException ex) {
                log.debug("[HCAD] semantic evidence refresh failed after LLM decision: type={}, resourceId={}",
                        key.type(), key.resourceId(), ex);
            }
        }
    }

    List<HcadSemanticEvidenceKey> decisionEvidenceKeys(SecurityEvent event, Map<String, Object> metadata) {
        return decisionEvidenceKeys(event, metadata, "ALLOW");
    }

    List<HcadSemanticEvidenceKey> decisionEvidenceKeys(
            SecurityEvent event,
            Map<String, Object> metadata,
            String learningAction) {
        if (hcadProperties == null || hcadProperties.getSemanticEvidence() == null) {
            return List.of();
        }
        String normalizedAction = learningAction(learningAction);
        if (normalizedAction == null) {
            return List.of();
        }
        HcadProperties.SemanticEvidenceSettings settings = hcadProperties.getSemanticEvidence();
        String userId = firstText(
                event != null ? event.getUserId() : null,
                text(metadata, "userId"));
        if (userId == null) {
            return List.of();
        }
        String normalizedPath = HcadRequestPathUtils.normalizePathText(firstText(
                text(metadata, "requestPath"),
                text(metadata, "requestUri"),
                text(metadata, "httpUri"),
                text(metadata, "protectableResourceUrl")));
        List<String> resourceIds = resourceIdentifiers(metadata, normalizedPath);
        if (resourceIds.isEmpty()) {
            return List.of();
        }
        int dimension = Math.max(1, hcadProperties.getVector().getEmbeddingDimension());
        String tenantId = firstText(text(metadata, "tenantId"), text(metadata, "organizationId"));
        if ("ALLOW".equals(normalizedAction)) {
            List<HcadSemanticEvidenceKey> keys = new ArrayList<>();
            for (String resourceId : resourceIds) {
                keys.add(HcadSemanticEvidenceKey.normalRequestSimilarity(
                        tenantId,
                        userId,
                        resourceId,
                        settings.getBaselineVersion(),
                        settings.getEmbeddingModel(),
                        dimension,
                        settings.getEvidenceVersion()));
            }
            return keys.stream().distinct().toList();
        }
        String policyVersion = firstText(
                text(metadata, "authorizationPolicyId"),
                text(metadata, "policyId"),
                text(metadata, "policyVersion"),
                "policy-unknown");
        String promptTemplateVersion = firstText(
                text(metadata, "promptContextContractVersion"),
                text(metadata, "promptTemplateVersion"),
                text(metadata, "promptTemplateKey"),
                text(metadata, "templateKey"),
                "prompt-unknown");
        List<HcadSemanticEvidenceKey> keys = new ArrayList<>();
        for (String resourceId : resourceIds) {
            keys.add(HcadSemanticEvidenceKey.riskRequestSimilarity(
                    tenantId,
                    userId,
                    resourceId,
                    policyVersion,
                    promptTemplateVersion,
                    settings.getEmbeddingModel(),
                    dimension,
                    settings.getEvidenceVersion()));
            keys.add(HcadSemanticEvidenceKey.resourceDecisionSummary(
                    tenantId,
                    resourceId,
                    policyVersion,
                    promptTemplateVersion,
                    settings.getEmbeddingModel(),
                    dimension,
                    settings.getEvidenceVersion()));
        }
        return keys.stream().distinct().toList();
    }

    private boolean enabled() {
        if (hcadProperties == null || hcadProperties.getSemanticEvidence() == null) {
            return false;
        }
        HcadProperties.SemanticEvidenceSettings settings = hcadProperties.getSemanticEvidence();
        return settings.isEnabled()
                && settings.getProvider() != HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider.DISABLED;
    }

    private static String learningAction(String action) {
        String normalized = action == null ? null : action.trim().toUpperCase();
        if ("ALLOW".equals(normalized) || "CHALLENGE".equals(normalized) || "BLOCK".equals(normalized)) {
            return normalized;
        }
        return null;
    }

    private static List<String> resourceIdentifiers(Map<String, Object> metadata, String normalizedPath) {
        LinkedHashSet<String> identifiers = new LinkedHashSet<>();
        addIdentifier(identifiers, text(metadata, "resourceId"));
        addIdentifier(identifiers, text(metadata, "protectableResourceId"));
        addIdentifier(identifiers, text(metadata, "requestedResourceId"));
        addIdentifier(identifiers, text(metadata, "protectedResourceId"));
        addIdentifier(identifiers, HcadRequestPathUtils.resourceFamily(normalizedPath));
        return List.copyOf(identifiers);
    }

    private static void addIdentifier(LinkedHashSet<String> identifiers, String value) {
        String text = firstText(value);
        if (text != null) {
            identifiers.add(text);
        }
    }

    private static String text(Map<String, Object> metadata, String key) {
        if (metadata == null || key == null) {
            return null;
        }
        return firstText(metadata.get(key));
    }

    private static String firstText(Object... values) {
        if (values == null) {
            return null;
        }
        for (Object value : values) {
            if (value == null) {
                continue;
            }
            String text = value.toString().trim();
            if (!text.isBlank()) {
                return text;
            }
        }
        return null;
    }
}

