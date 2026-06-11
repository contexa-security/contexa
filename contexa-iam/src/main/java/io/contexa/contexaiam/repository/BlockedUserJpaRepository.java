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
