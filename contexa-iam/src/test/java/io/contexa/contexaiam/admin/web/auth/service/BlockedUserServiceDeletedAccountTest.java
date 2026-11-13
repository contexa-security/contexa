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
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import io.contexa.contexaiam.testsupport.I18nTestSupport;
import org.junit.jupiter.api.BeforeEach;
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
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The record of a block outlives the decision store and is written back to it while it holds the block in force. The
 * purge of a deleted account therefore closes the account's records, or the block of the deleted account would return,
 * onto nobody or onto a later account created with the same name.
 */
@ExtendWith({MockitoExtension.class, I18nTestSupport.EnglishLocale.class})
@MockitoSettings(strictness = Strictness.LENIENT)
class BlockedUserServiceDeletedAccountTest {

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
        when(blockedUserJpaRepository.findByUserIdInAndStatusNot(any(), any())).thenAnswer(call -> {
            Collection<String> userIds = call.getArgument(0);
            BlockedUserStatus except = call.getArgument(1);
            return rows.stream().filter(row -> userIds.contains(row.getUserId()) && row.getStatus() != except).toList();
        });
        when(blockedUserJpaRepository.findUserIdsWhoseLatestRecordIsNot(any())).thenAnswer(call -> {
            BlockedUserStatus except = call.getArgument(0);
            return rows.stream().map(BlockedUser::getUserId).filter(Objects::nonNull).distinct()
                    .filter(userId -> rows.stream().filter(row -> userId.equals(row.getUserId()))
                            .max(Comparator.comparing(BlockedUser::getBlockedAt))
                            .map(latest -> latest.getStatus() != except).orElse(false))
                    .toList();
        });
        when(blockedUserJpaRepository.findFirstByUserIdOrderByBlockedAtDesc(anyString())).thenAnswer(call -> {
            String userId = call.getArgument(0);
            return rows.stream().filter(row -> userId.equals(row.getUserId()))
                    .max(Comparator.comparing(BlockedUser::getBlockedAt));
        });
    }

    private BlockedUser row(String userId, BlockedUserStatus status, int minute) {
        BlockedUser row = BlockedUser.builder().userId(userId).username(userId).status(status)
                .blockedAt(BASE.plusMinutes(minute)).blockCount(1).build();
        rows.add(row);
        return row;
    }

    @Test
    void theBlocksOfADeletedAccountAreClosedAndThoseOfTheOthersStay() {
        BlockedUser earlier = row("alice", BlockedUserStatus.RESOLVED, 0);
        BlockedUser blocked = row("alice", BlockedUserStatus.BLOCKED, 1);
        BlockedUser asked = row("alice", BlockedUserStatus.UNBLOCK_REQUESTED, 2);
        BlockedUser other = row("bob", BlockedUserStatus.BLOCKED, 3);
        assertThat(service.blocksInForce()).containsExactlyInAnyOrder("alice", "bob");

        int closed = service.resolveBlocksOfDeletedAccount("alice");

        assertThat(closed).isEqualTo(2);
        for (BlockedUser record : List.of(blocked, asked)) {
            assertThat(record.getStatus()).isEqualTo(BlockedUserStatus.RESOLVED);
            assertThat(record.getResolvedBy()).isEqualTo("SYSTEM");
            assertThat(record.getResolvedAction()).isEqualTo("ACCOUNT_DELETED");
            assertThat(record.getResolvedAt()).isNotNull();
            verify(blockedUserJpaRepository).save(record);
        }
        verify(blockedUserJpaRepository, never()).save(earlier);
        verify(blockedUserJpaRepository, never()).save(other);
        assertThat(other.getStatus()).isEqualTo(BlockedUserStatus.BLOCKED);
        // What the restorer reads: nothing of the deleted account is written back to the decision store.
        assertThat(service.isBlockInForce("alice")).isFalse();
        assertThat(service.blocksInForce()).containsExactly("bob");
    }

    /** A person named as an internal key is blocked under the key of their own. */
    @Test
    void aBlockRecordedUnderThePersonsOwnKeyIsClosedToo() {
        String name = "console::admin";
        String own = ZeroTrustUserKey.person(name);
        assertThat(own).isNotEqualTo(name);
        BlockedUser blocked = row(own, BlockedUserStatus.BLOCKED, 0);

        assertThat(service.resolveBlocksOfDeletedAccount(name)).isEqualTo(1);

        assertThat(blocked.getStatus()).isEqualTo(BlockedUserStatus.RESOLVED);
        assertThat(service.blocksInForce()).isEmpty();
    }

    @Test
    void anAccountWithoutABlockInForceChangesNothing() {
        BlockedUser earlier = row("alice", BlockedUserStatus.RESOLVED, 0);

        assertThat(service.resolveBlocksOfDeletedAccount("alice")).isZero();
        assertThat(service.resolveBlocksOfDeletedAccount(" ")).isZero();
        assertThat(service.resolveBlocksOfDeletedAccount(null)).isZero();

        verify(blockedUserJpaRepository, never()).save(any());
        assertThat(earlier.getResolvedBy()).isNull();
    }

    @Test
    void thePurgeOfAnAccountClosesItsBlockRecord() {
        BlockedUserService blockedUsers = mock(BlockedUserService.class);
        BlockRecordUserStatePurgeContributor contributor = new BlockRecordUserStatePurgeContributor(() -> blockedUsers);

        contributor.purge("alice");

        assertThat(contributor.name()).isEqualTo("block-record");
        verify(blockedUsers).resolveBlocksOfDeletedAccount("alice");
    }

    @Test
    void withoutABlockRecordThePurgeHasNothingToClose() {
        new BlockRecordUserStatePurgeContributor(() -> null).purge("alice");
    }
}
