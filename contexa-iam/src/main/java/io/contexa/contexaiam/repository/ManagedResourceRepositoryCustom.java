package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.dto.ResourceSearchCriteria;
import io.contexa.contexacommon.entity.ManagedResource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface ManagedResourceRepositoryCustom {
    
    Page<ManagedResource> findByCriteria(ResourceSearchCriteria criteria, Pageable pageable);
}
