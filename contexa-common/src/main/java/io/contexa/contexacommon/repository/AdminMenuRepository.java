package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.AdminMenu;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

public interface AdminMenuRepository extends JpaRepository<AdminMenu, Long> {

    @Query("SELECT DISTINCT m FROM AdminMenu m LEFT JOIN FETCH m.roles ORDER BY m.menuOrder ASC")
    List<AdminMenu> findAllWithRolesOrderByMenuOrder();

    List<AdminMenu> findByEnabledTrueOrderByMenuOrderAsc();

    List<AdminMenu> findByParentIdIsNullOrderByMenuOrderAsc();

    List<AdminMenu> findByParentIdOrderByMenuOrderAsc(Long parentId);

    List<AdminMenu> findAllByDataPageOrderByIdAsc(String dataPage);

    @Query("SELECT m.dataPage FROM AdminMenu m WHERE m.dataPage IS NOT NULL GROUP BY m.dataPage HAVING COUNT(m) > 1")
    List<String> findDuplicatedDataPages();

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Transactional(transactionManager = "contexaTransactionManager")
    @Query("UPDATE AdminMenu m SET m.parentId = :newParentId WHERE m.parentId = :oldParentId")
    int reassignChildren(@Param("oldParentId") Long oldParentId, @Param("newParentId") Long newParentId);

    void deleteByParentId(Long parentId);
}
