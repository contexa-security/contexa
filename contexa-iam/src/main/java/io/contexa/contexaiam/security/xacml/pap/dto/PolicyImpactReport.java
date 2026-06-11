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

public record PolicyImpactReport(
        int affectedUserCount,
        List<AffectedUser> affectedUsers,
        List<AffectedResource> affectedResources,
        AccessChangeSummary accessChangeSummary) {

    public record AffectedUser(
            Long userId,
            String username,
            List<String> roles,
            List<String> groups,
            String currentAccess,
            String newAccess,
            String changeType) {
    }

    public record AffectedResource(
            String identifier,
            String httpMethod,
            int currentPolicyCount,
            List<String> matchedPolicyNames) {
    }

    public record AccessChangeSummary(
            int gained,
            int lost,
            int changed,
            int unchanged) {
    }
}
