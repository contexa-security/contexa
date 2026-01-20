package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.Group;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface GroupRepository extends JpaRepository<Group, Long> {
    Optional<Group> findByName(String name);
    @Query("SELECT g FROM Group g LEFT JOIN FETCH g.groupRoles gr LEFT JOIN FETCH gr.role WHERE g.id = :id")
    Optional<Group> findByIdWithRoles(@Param("id") Long id);

    @Query("SELECT DISTINCT g FROM Group g LEFT JOIN FETCH g.groupRoles gr LEFT JOIN FETCH gr.role LEFT JOIN FETCH g.userGroups ug ORDER BY g.name ASC")
    List<Group> findAllWithRolesAndUsers();

    
    @Query("SELECT DISTINCT g FROM Group g " +
            "LEFT JOIN FETCH g.groupRoles gr " +
            "LEFT JOIN FETCH gr.role r " +
            "LEFT JOIN FETCH r.rolePermissions rp " +
            "LEFT JOIN FETCH rp.permission " +
            "ORDER BY g.name ASC")
    List<Group> findAllWithRolesAndPermissions();

    @Query("SELECT DISTINCT g FROM Group g " +
            "LEFT JOIN FETCH g.groupRoles gr " +
            "LEFT JOIN FETCH gr.role r " +
            "LEFT JOIN FETCH r.rolePermissions rp " +
            "LEFT JOIN FETCH rp.permission " +
            "WHERE g.id IN :ids")
    List<Group> findAllByIdWithRolesAndPermissions(@Param("ids") Collection<Long> ids);

    @Query("SELECT DISTINCT g FROM Group g LEFT JOIN FETCH g.groupRoles gr LEFT JOIN FETCH gr.role r LEFT JOIN FETCH r.rolePermissions rp LEFT JOIN FETCH rp.permission")
    List<Group> findAllWithRelations();
}