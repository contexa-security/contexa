package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationEventPublisher;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class BlockedUserServiceTest {

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

    @InjectMocks
    private BlockedUserService service;

    // ===== Helper methods =====

    private BlockedUser buildBlockedUser(Long id, String userId, BlockedUserStatus status) {
        return BlockedUser.builder()
                .id(id)
                .userId(userId)
                .username("user_" + userId)
                .requestId("req-" + id)
                .riskScore(0.85)
                .confidence(0.90)
                .reasoning("Suspicious activity")
                .blockedAt(LocalDateTime.now())
                .status(status)
                .blockCount(1)
                .sourceIp("192.168.1.1")
                .userAgent("TestAgent/1.0")
                .build();
    }

    // =========================================================================
    // recordBlock
    // =========================================================================

    @Nested
    @DisplayName("recordBlock")
    class RecordBlock {

        @Test
        @DisplayName("should create new block record when no existing BLOCKED entry")
        void shouldCreateNewRecord() {
            when(blockedUserJpaRepository.countByUserId("user1")).thenReturn(0);
            when(blockedUserJpaRepository.findFirstByUserIdAndStatusOrderByBlockedAtDesc("user1", BlockedUserStatus.BLOCKED))
                    .thenReturn(Optional.empty());

            service.recordBlock("req-1", "user1", "testuser", "Suspicious", "Suspicious activity detected", "10.0.0.1", "Agent/1.0");

            ArgumentCaptor<BlockedUser> captor = ArgumentCaptor.forClass(BlockedUser.class);
            verify(blockedUserJpaRepository).save(captor.capture());
            BlockedUser saved = captor.getValue();
            assertThat(saved.getUserId()).isEqualTo("user1");
            assertThat(saved.getStatus()).isEqualTo(BlockedUserStatus.BLOCKED);
            assertThat(saved.getBlockCount()).isEqualTo(1);
        }

        @Test
        @DisplayName("should update existing BLOCKED record and increment blockCount")
        void shouldUpdateExistingRecord() {
            BlockedUser existing = buildBlockedUser(1L, "user1", BlockedUserStatus.BLOCKED);
            existing.setBlockCount(2);
            when(blockedUserJpaRepository.countByUserId("user1")).thenReturn(2);
            when(blockedUserJpaRepository.findFirstByUserIdAndStatusOrderByBlockedAtDesc("user1", BlockedUserStatus.BLOCKED))
                    .thenReturn(Optional.of(existing));

            service.recordBlock("req-2", "user1", "testuser", "Repeated", "Repeated suspicious activity", "10.0.0.2", "Agent/2.0");

            verify(blockedUserJpaRepository).save(existing);
            assertThat(existing.getRequestId()).isEqualTo("req-2");
            assertThat(existing.getBlockCount()).isEqualTo(3);
            assertThat(existing.getRiskScore()).isEqualTo(0.95);
        }

        @Test
        @DisplayName("should audit block event")
        void shouldAuditBlockEvent() {
            when(blockedUserJpaRepository.countByUserId("user1")).thenReturn(0);
            when(blockedUserJpaRepository.findFirstByUserIdAndStatusOrderByBlockedAtDesc("user1", BlockedUserStatus.BLOCKED))
                    .thenReturn(Optional.empty());

            service.recordBlock("req-1", "user1", "testuser", "Suspicious", "Suspicious activity detected", "10.0.0.1", "Agent/1.0");

            verify(centralAuditFacade).recordAsync(any());
        }
    }

    // =========================================================================
    // resolveBlock
    // =========================================================================

    @Nested
    @DisplayName("resolveBlock")
    class ResolveBlock {

        @Test
        @DisplayName("should resolve most recent BLOCKED entry")
        void shouldResolveBlocked() {
            BlockedUser blocked = buildBlockedUser(1L, "user1", BlockedUserStatus.BLOCKED);
            when(blockedUserJpaRepository.findFirstByUserIdAndStatusOrderByBlockedAtDesc("user1", BlockedUserStatus.BLOCKED))
                    .thenReturn(Optional.of(blocked));

            service.resolveBlock("user1", "admin1", "UNBLOCK", "User verified");

            verify(blockedUserJpaRepository).save(blocked);
            assertThat(blocked.getStatus()).isEqualTo(BlockedUserStatus.RESOLVED);
            assertThat(blocked.getResolvedBy()).isEqualTo("admin1");
        }

        @Test
        @DisplayName("should do nothing when no BLOCKED entry found")
        void shouldDoNothingWhenNotFound() {
            when(blockedUserJpaRepository.findFirstByUserIdAndStatusOrderByBlockedAtDesc("user1", BlockedUserStatus.BLOCKED))
                    .thenReturn(Optional.empty());

            service.resolveBlock("user1", "admin1", "UNBLOCK", "Reason");

            verify(blockedUserJpaRepository, never()).save(any());
        }
    }

    // =========================================================================
    // resolveBlockById
    // =========================================================================

    @Nested
    @DisplayName("resolveBlockById")
    class ResolveBlockById {

        @Test
        @DisplayName("should resolve by ID")
        void shouldResolveById() {
            BlockedUser blocked = buildBlockedUser(1L, "user1", BlockedUserStatus.BLOCKED);
            when(blockedUserJpaRepository.findById(1L)).thenReturn(Optional.of(blocked));

            service.resolveBlockById(1L, "admin1", "UNBLOCK", "Approved");

            verify(blockedUserJpaRepository).save(blocked);
            assertThat(blocked.getStatus()).isEqualTo(BlockedUserStatus.RESOLVED);
        }

        @Test
        @DisplayName("should throw when not found")
        void shouldThrowWhenNotFound() {
            when(blockedUserJpaRepository.findById(999L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.resolveBlockById(999L, "admin1", "UNBLOCK", "Reason"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Blocked user not found");
        }

        @Test
        @DisplayName("should throw when already resolved")
        void shouldThrowWhenAlreadyResolved() {
            BlockedUser resolved = buildBlockedUser(1L, "user1", BlockedUserStatus.RESOLVED);
            when(blockedUserJpaRepository.findById(1L)).thenReturn(Optional.of(resolved));

            assertThatThrownBy(() -> service.resolveBlockById(1L, "admin1", "UNBLOCK", "Reason"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Already resolved");
        }
    }

    // =========================================================================
    // requestUnblock
    // =========================================================================

    @Nested
    @DisplayName("requestUnblock")
    class RequestUnblock {

        @Test
        @DisplayName("should set status to UNBLOCK_REQUESTED")
        void shouldSetUnblockRequested() {
            BlockedUser blocked = buildBlockedUser(1L, "user1", BlockedUserStatus.BLOCKED);
            when(blockedUserJpaRepository.findFirstByUserIdAndStatusOrderByBlockedAtDesc("user1", BlockedUserStatus.BLOCKED))
                    .thenReturn(Optional.of(blocked));

            service.requestUnblock("user1", "Please unblock me");

            verify(blockedUserJpaRepository).save(blocked);
            assertThat(blocked.getStatus()).isEqualTo(BlockedUserStatus.UNBLOCK_REQUESTED);
            assertThat(blocked.getUnblockReason()).isEqualTo("Please unblock me");
        }

        @Test
        @DisplayName("should do nothing when no BLOCKED entry")
        void shouldDoNothingWhenNotBlocked() {
            when(blockedUserJpaRepository.findFirstByUserIdAndStatusOrderByBlockedAtDesc("user1", BlockedUserStatus.BLOCKED))
                    .thenReturn(Optional.empty());

            service.requestUnblock("user1", "Reason");

            verify(blockedUserJpaRepository, never()).save(any());
        }
    }

    // =========================================================================
    // requestUnblockWithMfa
    // =========================================================================

    @Nested
    @DisplayName("requestUnblockWithMfa")
    class RequestUnblockWithMfa {

        @Test
        @DisplayName("should set UNBLOCK_REQUESTED with MFA flag")
        void shouldSetWithMfa() {
            BlockedUser blocked = buildBlockedUser(1L, "user1", BlockedUserStatus.BLOCKED);
            when(blockedUserJpaRepository.findFirstByUserIdAndStatusOrderByBlockedAtDesc("user1", BlockedUserStatus.BLOCKED))
                    .thenReturn(Optional.of(blocked));

            service.requestUnblockWithMfa("user1", "MFA verified", true);

            verify(blockedUserJpaRepository).save(blocked);
            assertThat(blocked.getStatus()).isEqualTo(BlockedUserStatus.UNBLOCK_REQUESTED);
            assertThat(blocked.getMfaVerified()).isTrue();
            assertThat(blocked.getMfaVerifiedAt()).isNotNull();
        }

        @Test
        @DisplayName("should set UNBLOCK_REQUESTED without MFA verified timestamp")
        void shouldSetWithoutMfaTimestamp() {
            BlockedUser blocked = buildBlockedUser(1L, "user1", BlockedUserStatus.BLOCKED);
            when(blockedUserJpaRepository.findFirstByUserIdAndStatusOrderByBlockedAtDesc("user1", BlockedUserStatus.BLOCKED))
                    .thenReturn(Optional.of(blocked));

            service.requestUnblockWithMfa("user1", "Reason", false);

            verify(blockedUserJpaRepository).save(blocked);
            assertThat(blocked.getMfaVerified()).isFalse();
            assertThat(blocked.getMfaVerifiedAt()).isNull();
        }
    }

    // =========================================================================
    // markMfaVerified
    // =========================================================================

    @Nested
    @DisplayName("markMfaVerified")
    class MarkMfaVerified {

        @Test
        @DisplayName("should mark MFA as verified")
        void shouldMarkVerified() {
            BlockedUser blocked = buildBlockedUser(1L, "user1", BlockedUserStatus.BLOCKED);
            when(blockedUserJpaRepository.findFirstByUserIdAndStatusOrderByBlockedAtDesc("user1", BlockedUserStatus.BLOCKED))
                    .thenReturn(Optional.of(blocked));

            service.markMfaVerified("user1");

            verify(blockedUserJpaRepository).save(blocked);
            assertThat(blocked.getMfaVerified()).isTrue();
            assertThat(blocked.getMfaVerifiedAt()).isNotNull();
        }

        @Test
        @DisplayName("should do nothing when no BLOCKED entry")
        void shouldDoNothingWhenNotFound() {
            when(blockedUserJpaRepository.findFirstByUserIdAndStatusOrderByBlockedAtDesc("user1", BlockedUserStatus.BLOCKED))
                    .thenReturn(Optional.empty());

            service.markMfaVerified("user1");

            verify(blockedUserJpaRepository, never()).save(any());
        }
    }

    // =========================================================================
    // markMfaFailed
    // =========================================================================

    @Nested
    @DisplayName("markMfaFailed")
    class MarkMfaFailed {

        @Test
        @DisplayName("should set status to MFA_FAILED and publish event")
        void shouldMarkFailed() {
            BlockedUser blocked = buildBlockedUser(1L, "user1", BlockedUserStatus.BLOCKED);
            when(blockedUserJpaRepository.findFirstByUserIdAndStatusOrderByBlockedAtDesc("user1", BlockedUserStatus.BLOCKED))
                    .thenReturn(Optional.of(blocked));

            service.markMfaFailed("user1");

            verify(blockedUserJpaRepository).save(blocked);
            assertThat(blocked.getStatus()).isEqualTo(BlockedUserStatus.MFA_FAILED);
            verify(eventPublisher).publishEvent(any(Object.class));
        }

        @Test
        @DisplayName("should do nothing when no BLOCKED entry")
        void shouldDoNothingWhenNotFound() {
            when(blockedUserJpaRepository.findFirstByUserIdAndStatusOrderByBlockedAtDesc("user1", BlockedUserStatus.BLOCKED))
                    .thenReturn(Optional.empty());

            service.markMfaFailed("user1");

            verify(blockedUserJpaRepository, never()).save(any());
            verify(eventPublisher, never()).publishEvent(any());
        }
    }

    // =========================================================================
    // getBlockedUsers
    // =========================================================================

    @Nested
    @DisplayName("getBlockedUsers")
    class GetBlockedUsers {

        @Test
        @DisplayName("should return BLOCKED status list")
        void shouldReturnBlockedList() {
            BlockedUser b1 = buildBlockedUser(1L, "user1", BlockedUserStatus.BLOCKED);
            when(blockedUserJpaRepository.findByStatusOrderByBlockedAtDesc(BlockedUserStatus.BLOCKED))
                    .thenReturn(List.of(b1));

            List<BlockedUser> result = service.getBlockedUsers();

            assertThat(result).hasSize(1);
            assertThat(result.get(0).getUserId()).isEqualTo("user1");
        }

        @Test
        @DisplayName("should return empty list when none blocked")
        void shouldReturnEmpty() {
            when(blockedUserJpaRepository.findByStatusOrderByBlockedAtDesc(BlockedUserStatus.BLOCKED))
                    .thenReturn(Collections.emptyList());

            List<BlockedUser> result = service.getBlockedUsers();

            assertThat(result).isEmpty();
        }
    }

    // =========================================================================
    // getUnblockRequested
    // =========================================================================

    @Nested
    @DisplayName("getUnblockRequested")
    class GetUnblockRequested {

        @Test
        @DisplayName("should return UNBLOCK_REQUESTED list")
        void shouldReturnUnblockRequestedList() {
            BlockedUser b1 = buildBlockedUser(1L, "user1", BlockedUserStatus.UNBLOCK_REQUESTED);
            when(blockedUserJpaRepository.findByStatusOrderByBlockedAtDesc(BlockedUserStatus.UNBLOCK_REQUESTED))
                    .thenReturn(List.of(b1));

            List<BlockedUser> result = service.getUnblockRequested();

            assertThat(result).hasSize(1);
        }
    }

    // =========================================================================
    // getAllBlockHistory
    // =========================================================================

    @Nested
    @DisplayName("getAllBlockHistory")
    class GetAllBlockHistory {

        @Test
        @DisplayName("should return all records ordered by blockedAt desc")
        void shouldReturnAll() {
            BlockedUser b1 = buildBlockedUser(1L, "user1", BlockedUserStatus.BLOCKED);
            BlockedUser b2 = buildBlockedUser(2L, "user2", BlockedUserStatus.RESOLVED);
            when(blockedUserJpaRepository.findAllByOrderByBlockedAtDesc()).thenReturn(List.of(b1, b2));

            List<BlockedUser> result = service.getAllBlockHistory();

            assertThat(result).hasSize(2);
        }
    }

    // =========================================================================
    // getBlockDetail
    // =========================================================================

    @Nested
    @DisplayName("getBlockDetail")
    class GetBlockDetail {

        @Test
        @DisplayName("should return detail by ID")
        void shouldReturnDetail() {
            BlockedUser blocked = buildBlockedUser(1L, "user1", BlockedUserStatus.BLOCKED);
            when(blockedUserJpaRepository.findById(1L)).thenReturn(Optional.of(blocked));

            Optional<BlockedUser> result = service.getBlockDetail(1L);

            assertThat(result).isPresent();
            assertThat(result.get().getUserId()).isEqualTo("user1");
        }

        @Test
        @DisplayName("should return empty when not found")
        void shouldReturnEmpty() {
            when(blockedUserJpaRepository.findById(999L)).thenReturn(Optional.empty());

            Optional<BlockedUser> result = service.getBlockDetail(999L);

            assertThat(result).isEmpty();
        }
    }

    // =========================================================================
    // deleteBlockRecord
    // =========================================================================

    @Nested
    @DisplayName("deleteBlockRecord")
    class DeleteBlockRecord {

        @Test
        @DisplayName("should delete resolved record")
        void shouldDeleteResolved() {
            BlockedUser resolved = buildBlockedUser(1L, "user1", BlockedUserStatus.RESOLVED);
            when(blockedUserJpaRepository.findById(1L)).thenReturn(Optional.of(resolved));

            service.deleteBlockRecord(1L);

            verify(blockedUserJpaRepository).delete(resolved);
        }

        @Test
        @DisplayName("should throw when record has BLOCKED status")
        void shouldThrowWhenBlocked() {
            BlockedUser blocked = buildBlockedUser(1L, "user1", BlockedUserStatus.BLOCKED);
            when(blockedUserJpaRepository.findById(1L)).thenReturn(Optional.of(blocked));

            assertThatThrownBy(() -> service.deleteBlockRecord(1L))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Cannot delete active block");
        }

        @Test
        @DisplayName("should throw when record not found")
        void shouldThrowWhenNotFound() {
            when(blockedUserJpaRepository.findById(999L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.deleteBlockRecord(999L))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Blocked user not found");
        }
    }
}
