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
package io.contexa.contexacore.autonomous.execution;

import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Locale;

public class DelegatedExecutionFingerprintService {

    public String computeRequestFingerprint(String httpMethod, String sourcePath, String resourceFingerprint) {
        return sha256(normalize(httpMethod) + "|" + normalize(sourcePath) + "|" + normalize(resourceFingerprint));
    }

    public String computeExecutionFingerprint(
            String tenantId,
            String clientId,
            DelegatedExecutionContext context,
            String capability,
            String operation,
            String resourceFingerprint,
            String requestFingerprint) {
        return sha256(String.join("|",
                normalize(tenantId),
                normalize(clientId),
                normalize(context != null ? context.executionMode() : null),
                normalize(context != null ? context.lineageState() : null),
                normalize(context != null ? context.actorUserId() : null),
                normalize(context != null ? context.agentId() : null),
                normalize(context != null ? context.agentRuntimeId() : null),
                normalize(context != null ? context.delegationId() : null),
                normalize(context != null ? context.parentExecutionId() : null),
                normalize(context != null ? context.taskIntent() : null),
                normalize(context != null ? context.taskPurpose() : null),
                join(context != null ? context.requestedScopes() : List.of()),
                join(context != null ? context.approvedScopes() : List.of()),
                join(context != null ? context.toolChain() : List.of()),
                normalize(context != null ? context.permitId() : null),
                normalize(context != null ? context.approvalId() : null),
                normalize(capability),
                normalize(operation),
                normalize(resourceFingerprint),
                normalize(requestFingerprint)));
    }

    public String resolveExecutionKey(
            String tenantId,
            String clientId,
            DelegatedExecutionContext context,
            String capability,
            String operation,
            String resourceFingerprint,
            String requestFingerprint) {
        if (context != null && StringUtils.hasText(context.executionId())) {
            return context.executionId().trim();
        }
        return computeExecutionFingerprint(tenantId, clientId, context, capability, operation, resourceFingerprint, requestFingerprint);
    }

    private String join(List<String> values) {
        if (values == null || values.isEmpty()) {
            return "-";
        }
        return values.stream().map(this::normalize).reduce((left, right) -> left + "," + right).orElse("-");
    }

    private String normalize(String value) {
        if (!StringUtils.hasText(value)) {
            return "-";
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(hash.length * 2);
            for (byte item : hash) {
                builder.append(String.format(Locale.ROOT, "%02x", item));
            }
            return builder.toString();
        }
        catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 algorithm is required", ex);
        }
    }
}