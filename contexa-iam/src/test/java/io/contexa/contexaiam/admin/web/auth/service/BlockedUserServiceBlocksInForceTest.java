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

import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import io.contexa.contexaiam.testsupport.I18nTestSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.MessageSource;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * The blocks the record holds in force, listed for an application that was given a name, are exactly the users for whom
 * {@code isBlockInForce} answers true: the latest record of the user is not resolved.
 */
@ExtendWith({MockitoExtension.class, I18nTestSupport.EnglishLocale.class})
@MockitoSettings(strictness = Strictness.LENIENT)
class BlockedUserServiceBlocksInForceTest {

    private static final LocalDateTime BASE = LocalDateTime.of(2026, 11, 1, 9, 0);

    @Mock
    private BlockedUserJpaRepository blockedUserJpaRepository;
    @Mock
    private AdminOverrideService adminOverrideService;
    @Mock
    private ZeroTrustActionRepository actionRedisRepository;
    @Mock
    private ApplicationEventPublisher eventPublisher;
    @Mock
    private CentralAuditFacade centralAuditFacade;
    @Mock
    private BlockingSignalBroadcaster blockingDecisionRegistry;
    @Spy
    private MessageSource messageSource = I18nTestSupport.englishMessageSource();
    @InjectMocks
    private BlockedUserService service;

    private final List<BlockedUser> rows = new ArrayList<>();

    @BeforeEach
    void theRecord() {
        when(blockedUserJpaRepository.findByStatusNot(any())).thenAnswer(call -> {
            BlockedUserStatus except = call.getArgument(0);
            return rows.stream().filter(row -> row.getStatus() != except).toList();
        });
        when(blockedUserJpaRepository.findFirstByUserIdOrderByBlockedAtDesc(anyString())).thenAnswer(call -> {
            String userId = call.getArgument(0);
            return rows.stream().filter(row -> userId.equals(row.getUserId()))
                    .max(Comparator.comparing(BlockedUser::getBlockedAt));
        });
    }

    private void row(String userId, BlockedUserStatus status, int minute) {
        rows.add(BlockedUser.builder().userId(userId).username(userId).status(status).blockedAt(BASE.plusMinutes(minute))
                .blockCount(1).build());
    }

    @Test
    @DisplayName("a user whose latest record is not resolved is listed, once, and a released one is not")
    void theLatestRecordDecides() {
        row("alice", BlockedUserStatus.BLOCKED, 1);
        row("bob", BlockedUserStatus.BLOCKED, 1);
        row("bob", BlockedUserStatus.RESOLVED, 5);
        row("carol", BlockedUserStatus.UNBLOCK_REQUESTED, 2);
        row("dave", BlockedUserStatus.TIMEOUT_RESPONDED, 3);
        row("erin", BlockedUserStatus.MFA_FAILED, 4);
        row("frank", BlockedUserStatus.RESOLVED, 1);
        row("gina", BlockedUserStatus.RESOLVED, 1);
        row("gina", BlockedUserStatus.BLOCKED, 6);
        row("hugh", BlockedUserStatus.BLOCKED, 1);
        row("hugh", BlockedUserStatus.BLOCKED, 2);
        row("console::ivy", BlockedUserStatus.BLOCKED, 7);

        List<String> listed = service.blocksInForce();

        assertThat(listed).containsExactlyInAnyOrder("alice", "carol", "dave", "erin", "gina", "hugh", "console::ivy");
        assertThat(listed).doesNotHaveDuplicates().doesNotContain("bob", "frank");
    }

    @Test
    @DisplayName("the list and isBlockInForce never part: every user of the record is listed exactly when it answers true")
    void theListIsWhatIsBlockInForceAnswers() {
        row("alice", BlockedUserStatus.BLOCKED, 1);
        row("bob", BlockedUserStatus.BLOCKED, 1);
        row("bob", BlockedUserStatus.RESOLVED, 5);
        row("carol", BlockedUserStatus.UNBLOCK_REQUESTED, 2);
        row("frank", BlockedUserStatus.RESOLVED, 1);
        row("gina", BlockedUserStatus.RESOLVED, 1);
        row("gina", BlockedUserStatus.BLOCKED, 6);
        row("erin", BlockedUserStatus.MFA_FAILED, 4);
        row("dave", BlockedUserStatus.TIMEOUT_RESPONDED, 3);

        Set<String> listed = Set.copyOf(service.blocksInForce());

        Set<String> inForce = rows.stream().map(BlockedUser::getUserId).distinct()
                .filter(service::isBlockInForce).collect(Collectors.toSet());
        assertThat(listed).isEqualTo(inForce);
        assertThat(listed).isNotEmpty();
    }

    @Test
    @DisplayName("an empty record lists nothing, and a record without a user id is left out")
    void anEmptyRecordListsNothing() {
        assertThat(service.blocksInForce()).isEmpty();

        row("", BlockedUserStatus.BLOCKED, 1);
        row(null, BlockedUserStatus.BLOCKED, 1);

        assertThat(service.blocksInForce()).isEmpty();
        assertThat(Optional.of(service.isBlockInForce(""))).contains(false);
    }
}
