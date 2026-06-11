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
package io.contexa.contexacore.autonomous.context.resolver;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.RoleScopeProfile;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.DefaultCanonicalSecurityContextProvider;

/**
 * Resolves RoleScopeProfile from metadata.
 * Extracted from DefaultCanonicalSecurityContextProvider - all business logic preserved.
 */
public class RoleScopeProfileResolver extends AbstractProfileResolver<RoleScopeProfile> {

    @Override
    protected RoleScopeProfile doResolve(Map<String, Object> metadata, CanonicalSecurityContext context) {
        String currentResourceFamily = text(
                metadata.get("currentResourceFamily"),
                metadata.get("current_resource_family"),
                context.getResource() != null ? context.getResource().getResourceType() : null);
        String currentActionFamily = text(
                metadata.get("currentActionFamily"),
                metadata.get("current_action_family"),
                context.getResource() != null ? context.getResource().getActionFamily() : null);

        RoleScopeProfile profile = RoleScopeProfile.builder()
                .summary(text(metadata.get("roleScopeSummary")))
                .currentResourceFamily(currentResourceFamily)
                .currentActionFamily(currentActionFamily)
                .expectedResourceFamilies(strings(metadata.get("expectedResourceFamilies"), metadata.get("allowedResourceFamilies")))
                .expectedActionFamilies(strings(metadata.get("expectedActionFamilies"), metadata.get("allowedActionFamilies")))
                .forbiddenResourceFamilies(strings(metadata.get("forbiddenResourceFamilies"), metadata.get("blockedResourceFamilies")))
                .forbiddenActionFamilies(strings(metadata.get("forbiddenActionFamilies"), metadata.get("blockedActionFamilies")))
                .normalApprovalPatterns(strings(metadata.get("normalApprovalPatterns"), metadata.get("approvalPatterns")))
                .normalEscalationPatterns(strings(metadata.get("normalEscalationPatterns"), metadata.get("escalationPatterns")))
                .recentPermissionChanges(strings(metadata.get("recentPermissionChanges"), metadata.get("permissionChangeEvents")))
                .resourceFamilyDrift(toBool(metadata.get("resourceFamilyDrift"), metadata.get("resource_family_drift")))
                .actionFamilyDrift(toBool(metadata.get("actionFamilyDrift"), metadata.get("action_family_drift")))
                .temporaryElevation(toBool(metadata.get("temporaryElevation"), metadata.get("temporary_elevation")))
                .temporaryElevationReason(text(metadata.get("temporaryElevationReason"), metadata.get("elevationReason"), metadata.get("temporary_elevation_reason")))
                .elevatedPrivilegeWindowActive(toBool(metadata.get("elevatedPrivilegeWindowActive"), metadata.get("elevated_privilege_window_active")))
                .elevationWindowSummary(text(metadata.get("elevationWindowSummary"), metadata.get("elevatedPrivilegeWindowSummary"), metadata.get("elevation_window_summary")))
                .build();

        if (!StringUtils.hasText(profile.getSummary())) {
            profile.setSummary(doBuildSummary(profile, context));
        }

        return profile;
    }

    @Override
    protected boolean doHasData(RoleScopeProfile profile) {
        return StringUtils.hasText(profile.getSummary())
                || StringUtils.hasText(profile.getCurrentResourceFamily())
                || StringUtils.hasText(profile.getCurrentActionFamily())
                || !profile.getExpectedResourceFamilies().isEmpty()
                || !profile.getExpectedActionFamilies().isEmpty()
                || !profile.getForbiddenResourceFamilies().isEmpty()
                || !profile.getForbiddenActionFamilies().isEmpty()
                || !profile.getNormalApprovalPatterns().isEmpty()
                || !profile.getNormalEscalationPatterns().isEmpty()
                || !profile.getRecentPermissionChanges().isEmpty()
                || profile.getTemporaryElevation() != null
                || StringUtils.hasText(profile.getTemporaryElevationReason())
                || profile.getElevatedPrivilegeWindowActive() != null
                || StringUtils.hasText(profile.getElevationWindowSummary());
    }

    @Override
    protected String doBuildSummary(RoleScopeProfile profile, CanonicalSecurityContext context) {
        if (context == null || context.getAuthorization() == null) {
            return buildSummaryWithoutAuthorization(profile);
        }
        List<String> facts = new ArrayList<>();
        if (!context.getAuthorization().getEffectiveRoles().isEmpty()) {
            facts.add("Effective roles: " + String.join(", ", context.getAuthorization().getEffectiveRoles()));
        }
        if (!context.getAuthorization().getScopeTags().isEmpty()) {
            facts.add("Scope tags: " + String.join(", ", context.getAuthorization().getScopeTags()));
        }
        if (Boolean.TRUE.equals(context.getAuthorization().getPrivileged())) {
            facts.add("Privileged flow is active");
        }
        if (profile != null && StringUtils.hasText(profile.getCurrentResourceFamily())) {
            facts.add("Current resource family: " + profile.getCurrentResourceFamily());
        }
        if (profile != null && StringUtils.hasText(profile.getCurrentActionFamily())) {
            facts.add("Current action family: " + profile.getCurrentActionFamily());
        }
        if (profile != null && !profile.getExpectedResourceFamilies().isEmpty()) {
            facts.add("Expected resource families: " + String.join(", ", profile.getExpectedResourceFamilies()));
        }
        if (profile != null && !profile.getExpectedActionFamilies().isEmpty()) {
            facts.add("Expected action families: " + String.join(", ", profile.getExpectedActionFamilies()));
        }
        if (profile != null && !profile.getForbiddenResourceFamilies().isEmpty()) {
            facts.add("Denied resource families: " + String.join(", ", profile.getForbiddenResourceFamilies()));
        }
        if (profile != null && !profile.getForbiddenActionFamilies().isEmpty()) {
            facts.add("Denied action families: " + String.join(", ", profile.getForbiddenActionFamilies()));
        }
        if (profile != null && Boolean.TRUE.equals(profile.getTemporaryElevation())) {
            facts.add("Temporary elevation is active");
        }
        return facts.isEmpty() ? null : String.join(" | ", facts);
    }

    private String buildSummaryWithoutAuthorization(RoleScopeProfile profile) {
        List<String> facts = new ArrayList<>();
        if (profile != null && StringUtils.hasText(profile.getCurrentResourceFamily())) {
            facts.add("Current resource family: " + profile.getCurrentResourceFamily());
        }
        if (profile != null && StringUtils.hasText(profile.getCurrentActionFamily())) {
            facts.add("Current action family: " + profile.getCurrentActionFamily());
        }
        if (profile != null && !profile.getExpectedResourceFamilies().isEmpty()) {
            facts.add("Expected resource families: " + String.join(", ", profile.getExpectedResourceFamilies()));
        }
        if (profile != null && !profile.getExpectedActionFamilies().isEmpty()) {
            facts.add("Expected action families: " + String.join(", ", profile.getExpectedActionFamilies()));
        }
        if (profile != null && !profile.getForbiddenResourceFamilies().isEmpty()) {
            facts.add("Denied resource families: " + String.join(", ", profile.getForbiddenResourceFamilies()));
        }
        if (profile != null && !profile.getForbiddenActionFamilies().isEmpty()) {
            facts.add("Denied action families: " + String.join(", ", profile.getForbiddenActionFamilies()));
        }
        return facts.isEmpty() ? null : String.join(" | ", facts);
    }

    @Override
    public void apply(RoleScopeProfile profile, CanonicalSecurityContext context) {
        context.setRoleScopeProfile(profile);
    }
}
