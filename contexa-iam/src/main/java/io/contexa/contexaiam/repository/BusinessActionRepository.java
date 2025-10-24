package io.contexa.contexaiam.repository;

import io.contexa.contexacommon.entity.business.BusinessAction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BusinessActionRepository extends JpaRepository<BusinessAction, Long> {
}
