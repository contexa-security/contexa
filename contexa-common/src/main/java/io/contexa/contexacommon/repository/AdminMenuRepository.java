package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.AdminMenu;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface AdminMenuRepository extends JpaRepository<AdminMenu, Long> {

    @Query("SELECT DISTINCT m FROM AdminMenu m LEFT JOIN FETCH m.roles ORDER BY m.menuOrder ASC")
    List<AdminMenu> findAllWithRolesOrderByMenuOrder();

    List<AdminMenu> findByEnabledTrueOrderByMenuOrderAsc();

    List<AdminMenu> findByParentIdIsNullOrderByMenuOrderAsc();

    List<AdminMenu> findByParentIdOrderByMenuOrderAsc(Long parentId);

    Optional<AdminMenu> findByDataPage(String dataPage);

    void deleteByParentId(Long parentId);
}
