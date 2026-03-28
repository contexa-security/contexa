package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {

    @Query("SELECT r FROM Role r WHERE r.expression = false " +
            "AND (:keyword IS NULL OR LOWER(r.roleName) LIKE LOWER(CONCAT('%', :keyword, '%')) " +
            "OR LOWER(r.roleDesc) LIKE LOWER(CONCAT('%', :keyword, '%')))")
    Page<Role> searchByKeyword(@Param("keyword") String keyword, Pageable pageable);
    Page<Role> findByRoleNameContainingIgnoreCaseOrRoleDescContainingIgnoreCase(String roleName, String roleDesc, Pageable pageable);

    Optional<Role> findByRoleName(String name);

    @Override
    void delete(Role role);

    @Query("select r from Role r where r.expression = false")
    List<Role> findAllRolesWithoutExpression();

    @Query("SELECT r FROM Role r LEFT JOIN FETCH r.rolePermissions rp LEFT JOIN FETCH rp.permission p LEFT JOIN FETCH p.managedResource WHERE r.id = :id")
    Optional<Role> findByIdWithPermissions(Long id);

    @Query("SELECT DISTINCT r FROM Role r LEFT JOIN FETCH r.rolePermissions rp LEFT JOIN FETCH rp.permission p LEFT JOIN FETCH p.managedResource")
    List<Role> findAllWithPermissions();

    @Query("SELECT DISTINCT r FROM Role r LEFT JOIN FETCH r.rolePermissions rp LEFT JOIN FETCH rp.permission p LEFT JOIN FETCH p.managedResource WHERE r.id IN :ids")
    List<Role> findAllByIdWithPermissions(@Param("ids") Collection<Long> ids);

    
    @Query("SELECT r FROM Role r " +
            "LEFT JOIN FETCH r.rolePermissions rp " +
            "LEFT JOIN FETCH rp.permission p " +
            "LEFT JOIN FETCH p.managedResource " +
            "WHERE r.id = :id")
    Optional<Role> findByIdWithPermissionsAndResources(@Param("id") Long id);
}