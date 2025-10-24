package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.entity.RoleHierarchyEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleHierarchyRepository extends JpaRepository<RoleHierarchyEntity, Long> {
    /**
     * 현재 활성화된 역할 계층 엔티티를 조회합니다.
     * @return 활성화된 RoleHierarchyEntity (Optional)
     */
    Optional<RoleHierarchyEntity> findByIsActiveTrue();

    /**
     * 특정 hierarchyString을 가진 역할 계층 엔티티를 조회합니다.
     * @param hierarchyString 계층 문자열
     * @return 해당 RoleHierarchyEntity (Optional)
     */
    Optional<RoleHierarchyEntity> findByHierarchyString(String hierarchyString);
}
