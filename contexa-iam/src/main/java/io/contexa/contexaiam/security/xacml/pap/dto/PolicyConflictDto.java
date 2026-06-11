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
package io.contexa.contexaiam.security.xacml.pap.dto;

public record PolicyConflictDto(
        Long newPolicyId,
        String newPolicyName,
        Long existingPolicyId,
        String existingPolicyName,
        String conflictDescription,
        Severity severity) {

    public enum Severity {
        CRITICAL,
        HIGH,
        MEDIUM,
        LOW
    }

    public PolicyConflictDto(Long newPolicyId, String newPolicyName,
                             Long existingPolicyId, String existingPolicyName,
                             String conflictDescription) {
        this(newPolicyId, newPolicyName, existingPolicyId, existingPolicyName,
                conflictDescription, Severity.HIGH);
    }
}
