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
package io.contexa.contexaiam.admin.web.dashboard;

import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationStore;
import io.contexa.contexacore.autonomous.agent.AgentRegistry;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import io.contexa.contexaiam.admin.web.agent.service.AgentContainmentAdminService;
import io.contexa.contexaiam.admin.web.auth.service.IpAccessRuleService;
import io.contexa.contexaiam.admin.web.auth.service.LastAdministratorGuard;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsService;
import io.contexa.contexaiam.admin.web.auth.service.VerificationCoverageService;
import io.contexa.contexaiam.admin.web.center.service.AccessCenterService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterCommandService;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleService;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustDecisionRecords;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import org.springframework.context.MessageSource;
import org.springframework.lang.Nullable;

/**
 * Where the dashboard's numbers come from (plan step 9): the screens' own services, so each card says what its screen
 * says. A source the application lacks (the agents without the autonomous plane) reads as none of it.
 */
public record DashboardSources(
        ZeroTrustConsoleService console,
        ZeroTrustDecisionRecords decisionRecords,
        DashboardQueries queries,
        AccessCenterService accessCenter,
        LastAdministratorGuard administrators,
        VerificationCoverageService verificationCoverage,
        RoleHierarchyRepository roleHierarchies,
        RoleRepository roles,
        PasswordPolicyService passwordPolicy,
        ManagedResourceRepository resources,
        PolicyRepository policies,
        PolicyValidationService policyValidation,
        PolicyCenterCommandService policyCenter,
        IpAccessRuleService ipRules,
        AuditLogRepository auditLog,
        SystemSettingsService systemSettings,
        PolicyCombiningProperties combining,
        @Nullable AgentRegistry agents,
        @Nullable DelegationRegistry delegations,
        @Nullable AgentConfirmationStore confirmations,
        @Nullable AgentContainmentAdminService containment,
        @Nullable MessageSource messages) {
}
