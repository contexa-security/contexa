package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.entity.FunctionGroup;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface FunctionGroupRepository extends JpaRepository<FunctionGroup, Long> { }
