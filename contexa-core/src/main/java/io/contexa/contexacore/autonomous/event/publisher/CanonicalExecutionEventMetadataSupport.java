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
package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacommon.domain.TruthValues;
import io.contexa.contexacommon.security.subject.SubjectClassifier;

import java.util.LinkedHashMap;
import java.util.Map;

public final class CanonicalExecutionEventMetadataSupport {

    private CanonicalExecutionEventMetadataSupport() {
    }

    public static Map<String, Object> enrich(Map<String, Object> payload) {
        Map<String, Object> metadata = payload == null ? new LinkedHashMap<>() : new LinkedHashMap<>(payload);
        // A1-3: who the request acts as is decided once (SubjectClassifier), the same way the canonical context and the
        // bridge decide it. A declared subject type or mode is one of the facts, so it stays unless agent facts or a
        // stated delegation contradict it; the recorded values then follow the decision.
        SubjectClassifier.Result subjectKind = SubjectClassifier.classify(SubjectClassifier.Facts.builder()
                .delegated(resolveBoolean(metadata.get("delegated")))
                .agentId(text(metadata.get("agentId")))
                .delegationId(text(metadata.get("delegationId")))
                .declaredSubjectType(text(metadata.get("executionSubjectType")))
                .declaredExecutionMode(text(metadata.get("executionMode")))
                .declaredLineageState(text(metadata.get("lineageState")))
                .actorType(text(metadata.get("actorType")))
                .principalType(text(metadata.get("principalType")))
                .serviceClientPrincipal(Boolean.TRUE.equals(resolveBoolean(metadata.get("serviceClientPrincipal"))))
                .build());
        String subjectType = subjectKind.subjectType();
        String executionMode = subjectKind.executionMode();
        String lineageState = subjectKind.lineageState();
        String protocolType = firstNonBlank(
                text(metadata.get("executionProtocolType")),
                text(metadata.get("protocolType")),
                text(metadata.get("sourceProtocol")),
                "UNKNOWN");

        metadata.put("executionSubjectKind", subjectKind.kind().name());
        metadata.put("executionSubjectType", subjectType);
        metadata.put("executionMode", executionMode);
        metadata.put("lineageState", lineageState);
        metadata.putIfAbsent("sourceProtocol", protocolType);

        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("subjectKind", subjectKind.kind().name());
        subject.put("subjectType", subjectType);
        subject.put("actorUserId", firstNonBlank(text(metadata.get("actorUserId")), text(metadata.get("userId"))));
        subject.put("agentId", text(metadata.get("agentId")));
        subject.put("tenantId", firstNonBlank(text(metadata.get("tenantId")), text(metadata.get("tenant_id"))));
        subject.put("organizationId", firstNonBlank(text(metadata.get("organizationId")), text(metadata.get("orgId"))));
        subject.put("clientId", text(metadata.get("clientId")));
        metadata.putIfAbsent("canonicalExecutionSubject", immutableCopyWithoutNulls(subject));

        Map<String, Object> execution = new LinkedHashMap<>();
        execution.put("executionId", firstNonBlank(text(metadata.get("executionId")), text(metadata.get("requestId"))));
        execution.put("delegationId", text(metadata.get("delegationId")));
        execution.put("executionMode", executionMode);
        execution.put("lineageState", lineageState);
        execution.put("objectiveId", firstNonBlank(text(metadata.get("objectiveId")), text(metadata.get("taskPurpose"))));
        execution.put("objectiveFamily", text(metadata.get("objectiveFamily")));
        execution.put("taskIntent", text(metadata.get("taskIntent")));
        execution.put("taskPurpose", text(metadata.get("taskPurpose")));
        execution.put("approvedScopes", metadata.get("approvedScopes"));
        execution.put("allowedOperations", metadata.get("allowedOperations"));
        execution.put("allowedResourceFamilies", firstNonBlankCollection(metadata.get("allowedResourceFamilies"), metadata.get("allowedResources")));
        execution.put("allowedToolChain", metadata.get("allowedToolChain"));
        execution.put("permitId", text(metadata.get("permitId")));
        execution.put("approvalId", text(metadata.get("approvalId")));
        execution.put("protocolType", protocolType);
        metadata.putIfAbsent("canonicalExecution", immutableCopyWithoutNulls(execution));
        return metadata;
    }

    private static Map<String, Object> immutableCopyWithoutNulls(Map<String, Object> source) {
        Map<String, Object> sanitized = new LinkedHashMap<>();
        if (source != null) {
            source.forEach((key, value) -> {
                if (key != null && value != null) {
                    sanitized.put(key, value);
                }
            });
        }
        return Map.copyOf(sanitized);
    }

    private static Object firstNonBlankCollection(Object primary, Object fallback) {
        return primary != null ? primary : fallback;
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    private static String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isBlank() ? null : text;
    }

    private static Boolean resolveBoolean(Object value) {
        return TruthValues.parse(value);
    }
}
