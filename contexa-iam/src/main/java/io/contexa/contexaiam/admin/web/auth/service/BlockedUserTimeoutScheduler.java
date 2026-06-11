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
package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.soar.event.SecurityActionEvent;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Scheduled job that checks for blocked users who have not requested unblock within timeout period.
 * Publishes SOAR_AUTO_RESPONSE event to trigger automatic IP blocking and session termination.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class BlockedUserTimeoutScheduler {

    private static final int TIMEOUT_HOURS = 24;

    private final BlockedUserJpaRepository blockedUserJpaRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final CentralAuditFacade centralAuditFacade;

    @Scheduled(fixedDelay = 3600000)
    @SchedulerLock(name = "blockedUserTimeoutCheck", lockAtMostFor = "PT30M", lockAtLeastFor = "PT1M")
    public void checkBlockedUserTimeout() {
        LocalDateTime threshold = LocalDateTime.now().minusHours(TIMEOUT_HOURS);
        List<BlockedUser> timedOut = blockedUserJpaRepository
                .findByStatusAndBlockedAtBefore(BlockedUserStatus.BLOCKED, threshold);

        for (BlockedUser user : timedOut) {
            log.error("Blocked user timeout - auto response triggered. userId={}, blockedAt={}",
                    user.getUserId(), user.getBlockedAt());

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("severity", "MEDIUM");
            metadata.put("threatType", "BLOCKED_USER_TIMEOUT_CONTAINMENT");
            metadata.put("zeroTrustAction", "BLOCK");
            metadata.put("securityEventType", "BLOCKED_USER_TIMEOUT");
            metadata.put("allowedTools", List.of("session_termination", "ip_blocking"));
            metadata.put("incidentId", user.getRequestId());
            metadata.put("sessionId", user.getRequestId());

            SecurityActionEvent event = SecurityActionEvent.builder()
                    .eventId(UUID.randomUUID().toString())
                    .actionType(SecurityActionEvent.ActionType.SOAR_AUTO_RESPONSE)
                    .userId(user.getUserId())
                    .sourceIp(user.getSourceIp())
                    .reason("Blocked user timeout - no unblock request within " + TIMEOUT_HOURS + " hours")
                    .triggeredBy("BlockedUserTimeoutScheduler")
                    .metadata(metadata)
                    .build();

            eventPublisher.publishEvent(event);

            user.setStatus(BlockedUserStatus.TIMEOUT_RESPONDED);
            blockedUserJpaRepository.save(user);

            centralAuditFacade.recordAsync(AuditRecord.builder()
                    .eventCategory(AuditEventCategory.SOAR_AUTO_RESPONSE)
                    .principalName(user.getUserId())
                    .resourceIdentifier(user.getRequestId())
                    .eventSource("IAM")
                    .clientIp(user.getSourceIp())
                    .action("SOAR_AUTO_RESPONSE")
                    .decision("TIMEOUT_RESPONDED")
                    .outcome("AUTO_BLOCKED")
                    .reason("No unblock request within " + TIMEOUT_HOURS + " hours")
                    .riskScore(user.getRiskScore())
                    .details(Map.of("userId", user.getUserId() != null ? user.getUserId() : "",
                            "blockedAt", user.getBlockedAt() != null ? user.getBlockedAt().toString() : "",
                            "timeoutHours", TIMEOUT_HOURS))
                    .build());
        }
    }
}



