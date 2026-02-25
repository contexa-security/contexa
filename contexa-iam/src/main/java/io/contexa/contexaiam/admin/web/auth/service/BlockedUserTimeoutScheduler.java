package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.soar.event.SecurityActionEvent;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;
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

    @Scheduled(fixedDelay = 3600000)
    public void checkBlockedUserTimeout() {
        LocalDateTime threshold = LocalDateTime.now().minusHours(TIMEOUT_HOURS);
        List<BlockedUser> timedOut = blockedUserJpaRepository
                .findByStatusAndBlockedAtBefore(BlockedUserStatus.BLOCKED, threshold);

        for (BlockedUser user : timedOut) {
            log.error("Blocked user timeout - auto response triggered. userId={}, blockedAt={}",
                    user.getUserId(), user.getBlockedAt());

            SecurityActionEvent event = SecurityActionEvent.builder()
                    .eventId(UUID.randomUUID().toString())
                    .actionType(SecurityActionEvent.ActionType.SOAR_AUTO_RESPONSE)
                    .userId(user.getUserId())
                    .sourceIp(user.getSourceIp())
                    .reason("Blocked user timeout - no unblock request within " + TIMEOUT_HOURS + " hours")
                    .triggeredBy("BlockedUserTimeoutScheduler")
                    .build();

            eventPublisher.publishEvent(event);

            user.setStatus(BlockedUserStatus.TIMEOUT_RESPONDED);
            blockedUserJpaRepository.save(user);
        }
    }
}
