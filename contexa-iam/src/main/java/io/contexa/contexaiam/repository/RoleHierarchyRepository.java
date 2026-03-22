package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.entity.RoleHierarchyEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RoleHierarchyRepository extends JpaRepository<RoleHierarchyEntity, Long> {

    Optional<RoleHierarchyEntity> findByIsActiveTrue();

    List<RoleHierarchyEntity> findAllByIsActiveTrue();

    boolean existsByIsActiveTrue();

    Optional<RoleHierarchyEntity> findByHierarchyString(String hierarchyString);
}
