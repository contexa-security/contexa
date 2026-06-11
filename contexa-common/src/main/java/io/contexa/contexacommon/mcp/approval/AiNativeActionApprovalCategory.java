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
package io.contexa.contexacommon.mcp.approval;

import org.springframework.util.StringUtils;

import java.util.Arrays;

public enum AiNativeActionApprovalCategory {
    STANDARD_MUTATION(false),
    DESTRUCTIVE_TOOL(true),
    PRIVILEGED_EXPORT(true),
    CONNECTOR_RECONFIGURATION(true);

    private final boolean explicitApprovalRequired;

    AiNativeActionApprovalCategory(boolean explicitApprovalRequired) {
        this.explicitApprovalRequired = explicitApprovalRequired;
    }

    public boolean explicitApprovalRequired() {
        return explicitApprovalRequired;
    }

    public static AiNativeActionApprovalCategory fromValue(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        return Arrays.stream(values())
                .filter(item -> item.name().equalsIgnoreCase(value.trim()))
                .findFirst()
                .orElse(null);
    }
}