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
package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.Users;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;


public interface UserRepository extends JpaRepository<Users, Long> {

    Optional<Users> findByUsername(String username);

    /** docs/agent A5-8: the account a risk signal names by its e-mail address. */
    Optional<Users> findFirstByEmailIgnoreCase(String email);

    List<Users> findByUsernameIn(Collection<String> usernames);

    Optional<Users> findByBridgeSubjectKey(String bridgeSubjectKey);

    /** The id of the account of this name, when it is one of Contexa's own and not a bridge copy of a user signed in elsewhere. */
    @Query("SELECT u.id FROM Users u WHERE u.username = :username AND u.bridgeManaged = false")
    Optional<Long> findOwnAccountId(@Param("username") String username);

    /** Bridge mirror users of one authenticated principal, across authentication sources and organizations. */
    List<Users> findByExternalSubjectIdAndBridgeManagedTrue(String externalSubjectId);

    Optional<Users> findByExternalSubjectIdAndAuthenticationSourceAndOrganizationId(
            String externalSubjectId,
            String authenticationSource,
            String organizationId
    );

    Optional<Users> findByExternalSubjectIdAndAuthenticationSourceAndOrganizationIdIsNull(
            String externalSubjectId,
            String authenticationSource
    );

    @Query("SELECT u FROM Users u " +
            "LEFT JOIN FETCH u.userGroups ug " +
            "LEFT JOIN FETCH ug.group g " +
            "LEFT JOIN FETCH g.groupRoles gr " +
            "LEFT JOIN FETCH gr.role r " +
            "LEFT JOIN FETCH r.rolePermissions rp " +
            "LEFT JOIN FETCH rp.permission p " +
            "LEFT JOIN FETCH u.userRoles ur " +
            "LEFT JOIN FETCH ur.role dr " +
            "LEFT JOIN FETCH dr.rolePermissions drp " +
            "LEFT JOIN FETCH drp.permission dp " +
            "WHERE u.username = :username")
    Optional<Users> findByUsernameWithGroupsRolesAndPermissions(@Param("username") String username);

    @Query("SELECT u FROM Users u " +
            "LEFT JOIN FETCH u.userGroups ug " +
            "LEFT JOIN FETCH ug.group g " +
            "LEFT JOIN FETCH g.groupRoles gr " +
            "LEFT JOIN FETCH gr.role r " +
            "LEFT JOIN FETCH u.userRoles ur " +
            "LEFT JOIN FETCH ur.role dr " +
            "WHERE u.username = :username")
    Optional<Users> findByUsernameWithGroupsAndRoles(@Param("username") String username);

    @Query("SELECT u FROM Users u " +
            "LEFT JOIN FETCH u.userGroups ug " +
            "LEFT JOIN FETCH ug.group g " +
            "LEFT JOIN FETCH g.groupRoles gr " +
            "LEFT JOIN FETCH gr.role r " +
            "LEFT JOIN FETCH r.rolePermissions rp " +
            "LEFT JOIN FETCH rp.permission p " +
            "LEFT JOIN FETCH u.userRoles ur " +
            "LEFT JOIN FETCH ur.role dr " +
            "LEFT JOIN FETCH dr.rolePermissions drp " +
            "LEFT JOIN FETCH drp.permission dp " +
            "WHERE u.id = :id")
    Optional<Users> findByIdWithGroupsRolesAndPermissions(@Param("id") Long id);

    @Query("SELECT DISTINCT u FROM Users u " +
            "LEFT JOIN FETCH u.userGroups ug " +
            "LEFT JOIN FETCH ug.group g " +
            "LEFT JOIN FETCH g.groupRoles gr " +
            "LEFT JOIN FETCH gr.role r " +
            "LEFT JOIN FETCH r.rolePermissions rp " +
            "LEFT JOIN FETCH rp.permission p")
    List<Users> findAllWithDetails();

    @Query("SELECT DISTINCT u FROM Users u " +
            "JOIN u.userGroups ug " +
            "JOIN ug.group g " +
            "JOIN g.groupRoles gr " +
            "JOIN gr.role r " +
            "WHERE u.mfaEnabled = false AND r.roleName = 'ADMIN'")
    List<Users> findAdminsWithMfaDisabled();

    
    @Query("SELECT count(DISTINCT u) FROM Users u JOIN u.userGroups ug JOIN ug.group g JOIN g.groupRoles gr JOIN gr.role r WHERE r.roleName = :roleName")
    long countByRoles(@Param("roleName") String roleName);

    
    @Query("SELECT count(DISTINCT u) FROM Users u JOIN u.userGroups ug JOIN ug.group g JOIN g.groupRoles gr JOIN gr.role r WHERE u.mfaEnabled = :mfaEnabled AND r.roleName = :roleName")
    long countByMfaEnabledAndRoles(@Param("mfaEnabled") boolean mfaEnabled, @Param("roleName") String roleName);

    long countByMfaEnabled(boolean mfaEnabled);

    /**
     * How many enabled accounts of Contexa's own, other than the one named, hold one of the roles, directly or through
     * a group of theirs.
     */
    @Query("SELECT count(DISTINCT u.id) FROM Users u LEFT JOIN u.userRoles ur LEFT JOIN u.userGroups ug "
            + "LEFT JOIN ug.group g LEFT JOIN g.groupRoles gr "
            + "WHERE u.id <> :excludedId AND u.enabled = true AND u.bridgeManaged = false "
            + "AND (ur.role.id IN :roleIds OR gr.role.id IN :roleIds)")
    long countEnabledOwnAccountsHoldingAnyRole(@Param("excludedId") Long excludedId,
                                               @Param("roleIds") Collection<Long> roleIds);

    /**
     * The user names of the enabled accounts of Contexa's own that hold one of the roles, directly or through a group
     * of theirs, in the order of the names; the page bounds how many are read.
     */
    @Query("SELECT DISTINCT u.username FROM Users u LEFT JOIN u.userRoles ur LEFT JOIN u.userGroups ug "
            + "LEFT JOIN ug.group g LEFT JOIN g.groupRoles gr "
            + "WHERE u.enabled = true AND u.bridgeManaged = false "
            + "AND (ur.role.id IN :roleIds OR gr.role.id IN :roleIds) ORDER BY u.username")
    List<String> findEnabledOwnUsernamesHoldingAnyRole(@Param("roleIds") Collection<Long> roleIds, Pageable pageable);

    /**
     * Q-1: the enabled accounts that could not answer a CHALLENGE: no passkey, and no address a code can reach. An agent
     * answers no factor made for people and is left out.
     *
     * @param mailDelivers  whether a mail server is configured; without one no address reaches anybody
     * @param syntheticMail the pattern of the addresses the bridge makes up
     * @param agentMail     the pattern of the addresses of agent accounts
     */
    @Query(value = """
            select count(*) from ctxa_users u
            where u.enabled = true
              and lower(u.email) not like :agentMail
              and (:mailDelivers = false
                   or position('@' in u.email) = 0
                   or lower(u.email) like :syntheticMail)
              and not exists (select 1 from ctxa_user_entities e
                              join ctxa_user_credentials c on c.user_entity_user_id = e.id
                              where e.name = u.username)
            """, nativeQuery = true)
    long countWithoutVerificationFactor(@Param("mailDelivers") boolean mailDelivers,
                                        @Param("syntheticMail") String syntheticMail,
                                        @Param("agentMail") String agentMail);

    @Query("SELECT DISTINCT u FROM Users u LEFT JOIN FETCH u.userGroups ug LEFT JOIN FETCH ug.group g LEFT JOIN FETCH g.groupRoles gr LEFT JOIN FETCH gr.role r LEFT JOIN FETCH r.rolePermissions rp LEFT JOIN FETCH rp.permission")
    List<Users> findAllWithGroups();

    Page<Users> findByUsernameContainingIgnoreCaseOrNameContainingIgnoreCase(
            String username, String name, Pageable pageable);

    /**
     * Atomically increment the failed_login_attempts counter for the given username.
     * Single SQL UPDATE — no read-modify-write race condition.
     * <p>flushAutomatically/clearAutomatically ensure the persistence context is in sync
     * with the database so a follow-up SELECT in the same transaction sees the updated row
     * instead of a stale first-level cache entry.</p>
     * @return number of rows updated (1 if user exists, 0 otherwise)
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE Users u SET u.failedLoginAttempts = u.failedLoginAttempts + 1 WHERE u.username = :username")
    int incrementFailedAttempts(@Param("username") String username);

    /**
     * Read the current failedLoginAttempts after an atomic increment.
     * Use within the same transaction as {@link #incrementFailedAttempts(String)}.
     */
    @Query("SELECT u.failedLoginAttempts FROM Users u WHERE u.username = :username")
    Optional<Integer> findFailedAttempts(@Param("username") String username);

    /**
     * Atomically lock an account that is not locked yet and set lockExpiresAt. A lock that is in force is left as it
     * is: an attempt made during a lock must not move its end, or anyone could keep the account locked by trying it
     * from time to time.
     * @return rows updated (1 if the account was locked by this call, 0 otherwise)
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE Users u SET u.accountLocked = true, u.lockExpiresAt = :expiresAt " +
            "WHERE u.username = :username AND u.accountLocked = false")
    int lockAccount(@Param("username") String username, @Param("expiresAt") LocalDateTime expiresAt);

    /**
     * Atomically reset the failed-attempt counter and lock state on success.
     * @return rows updated
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE Users u SET u.failedLoginAttempts = 0, u.accountLocked = false, " +
            "u.lockExpiresAt = null, u.lastLoginAt = :lastLoginAt, u.lastLoginIp = :lastLoginIp " +
            "WHERE u.username = :username")
    int resetOnSuccess(@Param("username") String username,
                       @Param("lastLoginAt") LocalDateTime lastLoginAt,
                       @Param("lastLoginIp") String lastLoginIp);

    /**
     * Atomically clear lock when the lock window has expired (idempotent self-heal).
     * Only clears when accountLocked = true AND lockExpiresAt &lt; :now.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE Users u SET u.accountLocked = false, u.failedLoginAttempts = 0, u.lockExpiresAt = null " +
            "WHERE u.username = :username AND u.accountLocked = true AND u.lockExpiresAt IS NOT NULL " +
            "AND u.lockExpiresAt < :now")
    int clearExpiredLock(@Param("username") String username, @Param("now") LocalDateTime now);

    /**
     * An administrator's release of a lock ahead of its end. It clears the account's lock and count, not the count of the
     * address the failures came from: that one stands for everyone who tried from there.
     * @return rows updated (1 if the account was locked, 0 otherwise)
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE Users u SET u.accountLocked = false, u.failedLoginAttempts = 0, u.lockExpiresAt = null " +
            "WHERE u.id = :id AND u.accountLocked = true")
    int clearLock(@Param("id") Long id);
}
