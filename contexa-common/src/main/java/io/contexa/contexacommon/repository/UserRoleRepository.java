package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.UserRole;
import io.contexa.contexacommon.entity.UserRoleId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface UserRoleRepository extends JpaRepository<UserRole, UserRoleId> {

    @Query("SELECT ur FROM UserRole ur JOIN FETCH ur.role WHERE ur.user.id = :userId")
    List<UserRole> findByUserIdWithRole(@Param("userId") Long userId);

    @Query("SELECT ur FROM UserRole ur JOIN FETCH ur.user WHERE ur.role.id = :roleId")
    List<UserRole> findByRoleIdWithUser(@Param("roleId") Long roleId);

    void deleteByUserIdAndRoleId(Long userId, Long roleId);

    void deleteAllByUserId(Long userId);
}
