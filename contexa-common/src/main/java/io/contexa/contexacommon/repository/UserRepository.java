package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.Users;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;


public interface UserRepository extends JpaRepository<Users, Long> {

    @Cacheable(value = "usersWithAuthorities", key = "#username")
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

    @Cacheable(value = "usersWithAuthorities", key = "#id")
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
}