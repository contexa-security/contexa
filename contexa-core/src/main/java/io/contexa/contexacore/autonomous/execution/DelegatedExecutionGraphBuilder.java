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


import java.time.LocalDateTime;

public class DelegatedExecutionGraphBuilder {

    private final DelegatedExecutionFingerprintService delegatedExecutionFingerprintService;

    public DelegatedExecutionGraphBuilder(DelegatedExecutionFingerprintService delegatedExecutionFingerprintService) {
        this.delegatedExecutionFingerprintService = delegatedExecutionFingerprintService != null
                ? delegatedExecutionFingerprintService
                : new DelegatedExecutionFingerprintService();
    }

    public DelegatedExecutionGraph build(
            String tenantId,
            String clientId,
            boolean serviceClientPrincipal,
            DelegatedExecutionContext context,
            String capability,
            String operation,
            String sourcePath,
            String httpMethod,
            String resourceFingerprint,
            LocalDateTime observedAt) {
        String requestFingerprint = delegatedExecutionFingerprintService.computeRequestFingerprint(httpMethod, sourcePath, resourceFingerprint);
        String executionKey = delegatedExecutionFingerprintService.resolveExecutionKey(
                tenantId,
                clientId,
                context,
                capability,
                operation,
                resourceFingerprint,
                requestFingerprint);
        String executionFingerprint = delegatedExecutionFingerprintService.computeExecutionFingerprint(
                tenantId,
                clientId,
                context,
                capability,
                operation,
                resourceFingerprint,
                requestFingerprint);
        LocalDateTime effectiveObservedAt = observedAt != null ? observedAt : LocalDateTime.now();
        return new DelegatedExecutionGraph(
                executionKey,
                executionFingerprint,
                tenantId,
                clientId,
                serviceClientPrincipal,
                context,
                capability,
                operation,
                sourcePath,
                httpMethod,
                resourceFingerprint,
                requestFingerprint,
                effectiveObservedAt,
                context != null ? context.expiresAt() : null);
    }
}