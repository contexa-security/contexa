package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.entity.BlockedUser;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Collection;
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

    List<BlockedUser> findTop5ByStatusInOrderByBlockedAtDesc(Collection<BlockedUserStatus> statuses);

    @Query("SELECT b FROM BlockedUser b WHERE lower(b.username) LIKE :keyword ORDER BY b.blockedAt DESC")
    List<BlockedUser> searchByUsername(@Param("keyword") String keyword);

    @Query("SELECT b FROM BlockedUser b WHERE b.status = :status AND lower(b.username) LIKE :keyword ORDER BY b.blockedAt DESC")
    List<BlockedUser> searchByStatusAndUsername(@Param("status") BlockedUserStatus status, @Param("keyword") String keyword);

    @Query("SELECT b.status, COUNT(b) FROM BlockedUser b GROUP BY b.status")
    List<Object[]> countGroupByStatus();
}
