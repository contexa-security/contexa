package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.RolePermission;
import io.contexa.contexacommon.entity.RolePermissionId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;

public interface RolePermissionRepository extends JpaRepository<RolePermission, RolePermissionId> {

    @Query("SELECT rp FROM RolePermission rp JOIN FETCH rp.permission JOIN FETCH rp.role WHERE rp.role.id IN :roleIds")
    List<RolePermission> findByRoleIds(@Param("roleIds") Collection<Long> roleIds);
}
