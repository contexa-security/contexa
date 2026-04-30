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

    List<Users> findByUsernameIn(Collection<String> usernames);

    Optional<Users> findByBridgeSubjectKey(String bridgeSubjectKey);

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
     * Atomically lock the account and set lockExpiresAt.
     * @return rows updated
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE Users u SET u.accountLocked = true, u.lockExpiresAt = :expiresAt WHERE u.username = :username")
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
}
