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
package io.contexa.contexaiam.admin.web.monitoring.dto;

import io.contexa.contexaiam.admin.support.context.dto.RecentActivityDto;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import io.contexa.contexacommon.entity.AuditLog;
import java.util.List;

public record DashboardDto(
        StatisticsDto statistics,
        List<RecentActivityDto> recentActivities,
        List<RiskIndicatorDto> riskIndicators,
        SecurityScoreDto securityScore,
        PermissionMatrixDto permissionMatrix,
        PolicyStatusDto policyStatus,
        PolicyHealthDto policyHealth,
        List<AccessTrendDto> accessTrends,
        long resourceTotal,
        long resourceProtected,
        long resourceAwaiting,
        long blockedUserCount,
        long unblockRequestedCount,
        long soarAutoResponseCount,
        long mfaFailedCount,
        long resolvedCount,
        List<BlockedUser> recentBlockedUsers,
        // 24h security activity from audit_log
        long allowCount24h,
        long denyCount24h,
        long authSuccessCount24h,
        long authFailureCount24h,
        long securityDecisionCount24h,
        long adminOverrideCount24h,
        long securityErrorCount24h,
        long afterHoursAccessCount24h,
        long distinctIpCount24h,
        Double avgRiskScore24h,
        // Zero Trust decision breakdown (eventCategory=SECURITY_DECISION only)
        long ztAllowCount24h,
        long ztTotalCount24h,
        long challengeCount24h,
        long blockCount24h,
        long escalateCount24h,
        long policyChangeCount24h,
        long iamChangeCount24h,
        List<AuditLog> recentThreatEvents
) {}
