package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface PermissionRepository extends JpaRepository<Permission, Long> {
    Optional<Permission> findByName(String name);

    /**
     * [신규 추가] 여러 개의 권한 이름(name)으로 Permission 엔티티 목록을 조회합니다.
     * StudioVisualizerService 에서 사용됩니다.
     */
    List<Permission> findAllByNameIn(Set<String> names);

    /**
     * [오류 수정 및 성능 개선] isDefined = true인 권한을 조회할 때, N+1 문제를 방지하기 위해
     * Fetch Join을 사용하여 연관된 모든 엔티티를 한번의 쿼리로 가져옵니다.
     */
    @Query("SELECT p FROM Permission p " +
            "LEFT JOIN FETCH p.managedResource mr " +
            "WHERE mr.status <> io.contexa.contexacommon.entity.ManagedResource.Status.NEEDS_DEFINITION " +
            "AND mr.status <> io.contexa.contexacommon.entity.ManagedResource.Status.EXCLUDED")
    List<Permission> findDefinedPermissionsWithDetails();

    /**
     * 리소스 타입과 식별자로 권한을 조회합니다.
     * BusinessPolicyServiceImpl에서 Policy를 BusinessPolicyDto로 역변환할 때 사용됩니다.
     */
    @Query("SELECT p FROM Permission p " +
            "JOIN p.managedResource mr " +
            "WHERE mr.resourceType = :resourceType " +
            "AND mr.resourceIdentifier = :resourceIdentifier")
    List<Permission> findByResourceTypeAndIdentifier(
            @org.springframework.data.repository.query.Param("resourceType") io.contexa.contexacommon.entity.ManagedResource.ResourceType resourceType,
            @org.springframework.data.repository.query.Param("resourceIdentifier") String resourceIdentifier
    );
}