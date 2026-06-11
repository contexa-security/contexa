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
package io.contexa.contexaiam.aiam.labs.policy;

import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.std.rag.service.AbstractVectorLabService;
import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexaiam.aiam.protocol.response.PolicyResponse;
import org.springframework.ai.vectorstore.VectorStore;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationRequest;
import io.contexa.contexaiam.domain.dto.BusinessPolicyDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Slf4j
public class PolicyGenerationVectorService extends AbstractVectorLabService {

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    private final MessageSource messageSource;

    @Autowired
    public PolicyGenerationVectorService(VectorStore vectorStore,
                                        @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics,
                                        ContexaRagProperties ragProperties,
                                        MessageSource messageSource) {
        super(vectorStore, vectorStoreMetrics, ragProperties);
        this.messageSource = messageSource;
    }

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @Override
    protected String getLabName() {
        return "PolicyGeneration";
    }

    @Override
    protected String getDocumentType() {
        return VectorDocumentType.POLICY_GENERATION.getValue();
    }

    @Override
    protected Document enrichLabSpecificMetadata(Document document) {
        return document;
    }

    @Override
    protected void validateLabSpecificDocument(Document document) {
        Map<String, Object> metadata = document.getMetadata();

        if (!metadata.containsKey("organizationId") &&
            !metadata.containsKey("policyName") &&
            !metadata.containsKey("naturalLanguageQuery")) {
            throw new IllegalArgumentException(
                "Policy Generation document must contain at least one of: organizationId, policyName, naturalLanguageQuery");
        }

        String text = document.getText();
        if (text == null || text.trim().length() < 10) {
            throw new IllegalArgumentException(msg("msg.policy.content.too.short"));
        }

        if (text.length() > 10000) {
            throw new IllegalArgumentException(msg("msg.policy.content.too.long"));
        }
    }

    @Override
    protected Map<String, Object> getLabSpecificFilters() {
        Map<String, Object> filters = new HashMap<>();
        filters.put("labName", getLabName());
        return filters;
    }

    public void storePolicyGenerationRequest(PolicyGenerationRequest request) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("naturalLanguageQuery", request.getNaturalLanguageQuery());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", VectorDocumentType.POLICY_GENERATION_REQUEST.getValue());
            metadata.put("requestId", UUID.randomUUID().toString());

            String requestText = String.format(
                "Policy generation request: '%s'",
                request.getNaturalLanguageQuery()
            );

            Document requestDoc = new Document(requestText, metadata);
            storeDocument(requestDoc);

        } catch (Exception e) {
            log.error("[PolicyGenerationVectorService] Policy generation request storage failed", e);
            throw new VectorStoreException("Policy generation request storage failed: " + e.getMessage(), e);
        }
    }

    public void storeGeneratedPolicy(PolicyGenerationRequest request, PolicyResponse policyDto) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("originalQuery", request.getNaturalLanguageQuery());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", VectorDocumentType.GENERATED_POLICY.getValue());
            metadata.put("policyId", UUID.randomUUID().toString());

            BusinessPolicyDto policy = policyDto.getPolicyData();
            if (policy != null) {
                metadata.put("policyName", policy.getPolicyName());
                metadata.put("policyDescription", policy.getDescription());
                metadata.put("roleCount", policy.getRoleIds() != null ? policy.getRoleIds().size() : 0);
                metadata.put("permissionCount", policy.getPermissionIds() != null ? policy.getPermissionIds().size() : 0);
                metadata.put("effect", policy.getEffect() != null ? policy.getEffect().name() : "ALLOW");
            }

            // Build detailed policy text for better RAG retrieval
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("AI generated policy: '%s' - %s",
                    policy != null ? policy.getPolicyName() : "Unknown",
                    policy != null ? policy.getDescription() : "No description"));
            if (policy != null) {
                sb.append(String.format(" | Effect: %s", policy.getEffect() != null ? policy.getEffect().name() : "ALLOW"));
                if (policy.getRoleIds() != null && !policy.getRoleIds().isEmpty()) {
                    sb.append(" | RoleIDs: ").append(policy.getRoleIds());
                }
                if (policy.getPermissionIds() != null && !policy.getPermissionIds().isEmpty()) {
                    sb.append(" | PermIDs: ").append(policy.getPermissionIds());
                }
                if (policy.getCrudPermissions() != null && !policy.getCrudPermissions().isEmpty()) {
                    sb.append(" | CRUD: ").append(policy.getCrudPermissions());
                }
                if (policy.getReasoning() != null) {
                    sb.append(" | Reasoning: ").append(policy.getReasoning());
                }
            }
            // Include role/permission name maps for richer context
            if (policyDto.getRoleIdToNameMap() != null && !policyDto.getRoleIdToNameMap().isEmpty()) {
                sb.append(" | Roles: ").append(policyDto.getRoleIdToNameMap().values());
            }
            if (policyDto.getPermissionIdToNameMap() != null && !policyDto.getPermissionIdToNameMap().isEmpty()) {
                sb.append(" | Permissions: ").append(policyDto.getPermissionIdToNameMap().values());
            }
            String policyText = sb.toString();

            Document policyDoc = new Document(policyText, metadata);
            storeDocument(policyDoc);

        } catch (Exception e) {
            log.error("[PolicyGenerationVectorService] AI generated policy storage failed", e);
            throw new VectorStoreException("AI generated policy storage failed: " + e.getMessage(), e);
        }
    }

    public List<Document> findSimilarPolicies(String query, int topK) {
        Map<String, Object> filters = new HashMap<>();
        filters.put("topK", topK);
        return searchSimilar(query, filters);
    }
}
