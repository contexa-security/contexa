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

import java.util.List;

public record DuplicatePolicyDto(String reason, List<Long> policyIds, String policySignature,
                                  DuplicateType type) {

    public enum DuplicateType {
        EXACT,
        SEMANTIC,
        SUBSET,
        HIERARCHY_SUBSUME
    }

    public DuplicatePolicyDto(String reason, List<Long> policyIds, String policySignature) {
        this(reason, policyIds, policySignature, DuplicateType.EXACT);
    }
}