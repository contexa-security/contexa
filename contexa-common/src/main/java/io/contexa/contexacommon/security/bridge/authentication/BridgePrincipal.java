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
package io.contexa.contexacommon.security.bridge.authentication;

import java.io.Serializable;
import java.security.Principal;

public record BridgePrincipal(
        String username,
        String principalId,
        String displayName,
        String principalType,
        String tenantId,
        String organizationId,
        String orgId,
        String department,
        Long internalUserId,
        String bridgeSubjectKey,
        boolean bridgeManaged,
        boolean externalAuthOnly
) implements Principal, Serializable {

    @Override
    public String getName() {
        if (username != null && !username.isBlank()) {
            return username;
        }
        return principalId;
    }

    public String getExternalSubjectId() {
        return principalId;
    }
}
