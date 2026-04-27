package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.GroupRolePermission;
import io.contexa.contexacommon.entity.GroupRolePermissionId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;

public interface GroupRolePermissionRepository extends JpaRepository<GroupRolePermission, GroupRolePermissionId> {

    @Query("SELECT grp FROM GroupRolePermission grp JOIN FETCH grp.permission WHERE grp.group.id = :groupId AND grp.role.id = :roleId")
    List<GroupRolePermission> findByGroupIdAndRoleId(@Param("groupId") Long groupId, @Param("roleId") Long roleId);

    @Query("SELECT grp FROM GroupRolePermission grp JOIN FETCH grp.permission JOIN FETCH grp.role WHERE grp.group.id = :groupId")
    List<GroupRolePermission> findByGroupId(@Param("groupId") Long groupId);

    @Query("SELECT grp FROM GroupRolePermission grp JOIN FETCH grp.group JOIN FETCH grp.permission JOIN FETCH grp.role WHERE grp.group.id IN :groupIds")
    List<GroupRolePermission> findByGroupIds(@Param("groupIds") Collection<Long> groupIds);

    @Modifying
    @Query("DELETE FROM GroupRolePermission grp WHERE grp.group.id = :groupId AND grp.role.id = :roleId")
    void deleteByGroupIdAndRoleId(@Param("groupId") Long groupId, @Param("roleId") Long roleId);

    @Modifying
    @Query("DELETE FROM GroupRolePermission grp WHERE grp.group.id = :groupId")
    void deleteByGroupId(@Param("groupId") Long groupId);
}
