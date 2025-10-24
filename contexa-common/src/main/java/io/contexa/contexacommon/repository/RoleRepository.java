package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRoleName(String name);

    @Override
    void delete(Role role);

    @Query("select r from Role r where r.isExpression = 'N'")
    List<Role> findAllRolesWithoutExpression();

    @Query("SELECT r FROM Role r LEFT JOIN FETCH r.rolePermissions p WHERE r.id = :id")
    Optional<Role> findByIdWithPermissions(Long id);

    /**
     * N+1 문제 해결을 위해 모든 Role과 연관된 Permission을 함께 조회합니다.
     * @return Role 리스트
     */
    @Query("SELECT DISTINCT r FROM Role r LEFT JOIN FETCH r.rolePermissions rp LEFT JOIN FETCH rp.permission")
    List<Role> findAllWithPermissions();

    @Query("SELECT DISTINCT r FROM Role r LEFT JOIN FETCH r.rolePermissions rp LEFT JOIN FETCH rp.permission WHERE r.id IN :ids")
    List<Role> findAllByIdWithPermissions(@Param("ids") Collection<Long> ids);

    /**
     * 권한 및 권한에 연결된 리소스까지 모두 fetch join 하여 조회합니다.
     * PolicySynchronizationService 에서 사용됩니다.
     */
    @Query("SELECT r FROM Role r " +
            "LEFT JOIN FETCH r.rolePermissions rp " +
            "LEFT JOIN FETCH rp.permission p " +
            "LEFT JOIN FETCH p.managedResource " +
            "WHERE r.id = :id")
    Optional<Role> findByIdWithPermissionsAndResources(@Param("id") Long id);
}