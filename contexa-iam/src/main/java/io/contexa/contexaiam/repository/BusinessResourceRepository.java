package io.contexa.contexaiam.repository;

import io.contexa.contexacommon.entity.business.BusinessResource;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BusinessResourceRepository extends JpaRepository<BusinessResource, Long> {
}