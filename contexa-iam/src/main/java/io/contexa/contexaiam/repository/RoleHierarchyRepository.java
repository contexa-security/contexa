package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.entity.RoleHierarchyEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RoleHierarchyRepository extends JpaRepository<RoleHierarchyEntity, Long> {

    Optional<RoleHierarchyEntity> findByIsActiveTrue();

    List<RoleHierarchyEntity> findAllByIsActiveTrue();

    boolean existsByIsActiveTrue();

    Optional<RoleHierarchyEntity> findByHierarchyString(String hierarchyString);

    Page<RoleHierarchyEntity> findAll(Pageable pageable);

    @Query("SELECT h FROM RoleHierarchyEntity h WHERE lower(h.hierarchyString) LIKE :keyword OR lower(h.description) LIKE :keyword ORDER BY h.id DESC")
    Page<RoleHierarchyEntity> searchByKeyword(@Param("keyword") String keyword, Pageable pageable);
}
