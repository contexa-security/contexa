package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.entity.BlockedUser;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface BlockedUserJpaRepository extends JpaRepository<BlockedUser, Long> {

    List<BlockedUser> findByStatusOrderByBlockedAtDesc(BlockedUserStatus status);

    Optional<BlockedUser> findFirstByUserIdAndStatusOrderByBlockedAtDesc(String userId, BlockedUserStatus status);

    Optional<BlockedUser> findFirstByUserIdOrderByBlockedAtDesc(String userId);

    int countByUserId(String userId);

    List<BlockedUser> findByStatusAndBlockedAtBefore(BlockedUserStatus status, LocalDateTime threshold);

    List<BlockedUser> findAllByOrderByBlockedAtDesc();

    long countByStatus(BlockedUserStatus status);

    List<BlockedUser> findTop5ByStatusOrderByBlockedAtDesc(BlockedUserStatus status);
}
