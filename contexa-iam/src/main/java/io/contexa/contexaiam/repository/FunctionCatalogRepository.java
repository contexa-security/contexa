package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.entity.FunctionCatalog;
import io.contexa.contexacommon.entity.ManagedResource;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface FunctionCatalogRepository extends JpaRepository<FunctionCatalog, Long> {

    Optional<FunctionCatalog> findByManagedResource(ManagedResource managedResource);

    /**
     * 명명된 파라미터를 사용하여 UNCONFIRMED 상태의 기능을 조회합니다.
     */
    @Query("SELECT fc FROM FunctionCatalog fc " +
            "JOIN FETCH fc.managedResource " +
            "WHERE fc.status = :status " +
            "ORDER BY fc.id ASC")
    List<FunctionCatalog> findFunctionsByStatusWithDetails(@Param("status") FunctionCatalog.CatalogStatus status);

    /**
     * 명명된 파라미터를 사용하여 관리 가능한(UNCONFIRMED가 아닌) 기능들을 조회합니다.
     */
    @Query("SELECT fc FROM FunctionCatalog fc " +
            "JOIN FETCH fc.managedResource " +
            "LEFT JOIN FETCH fc.functionGroup " +
            "WHERE fc.status <> :status " +
            "ORDER BY fc.functionGroup.name, fc.friendlyName ASC")
    List<FunctionCatalog> findAllByStatusNotWithDetails(@Param("status") FunctionCatalog.CatalogStatus status);
    /**
     * [신규] '권한 정의' 화면을 위해 ACTIVE 상태인 모든 기능을 조회합니다.
     */
    @Query("SELECT fc FROM FunctionCatalog fc " +
            "WHERE fc.status = 'ACTIVE'")
    List<FunctionCatalog> findAllActiveFunctions();

    @Query("SELECT fc FROM FunctionCatalog fc JOIN FETCH fc.managedResource LEFT JOIN FETCH fc.functionGroup")
    List<FunctionCatalog> findAllWithDetails();
}
