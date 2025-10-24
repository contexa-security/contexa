package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.entity.PolicyTemplate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PolicyTemplateRepository extends JpaRepository<PolicyTemplate, Long> {
    List<PolicyTemplate> findByCategory(String category);
}