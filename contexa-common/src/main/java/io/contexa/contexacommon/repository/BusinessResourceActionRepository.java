package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.business.BusinessResource;
import io.contexa.contexacommon.entity.business.BusinessResourceAction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;


@Repository
public interface BusinessResourceActionRepository extends JpaRepository<BusinessResourceAction, BusinessResourceAction.BusinessResourceActionId> {
    
    
    @Query("SELECT bra.businessResource FROM BusinessResourceAction bra WHERE bra.businessResource.name = :resourceId")
    Optional<BusinessResource> findByResourceIdentifier(@Param("resourceId") String resourceId);
    
    
    @Query("SELECT 10.5 FROM BusinessResourceAction bra WHERE bra.businessResource.name = :resourceId")
    double getAverageAccessesPerDay(@Param("resourceId") String resourceId);
    
    
    @Query("SELECT br.resourceType FROM BusinessResource br WHERE br.name = :resourceId")
    Optional<String> getResourceSensitivityLevel(@Param("resourceId") String resourceId);
    
    
    @Query("SELECT COUNT(bra) FROM BusinessResourceAction bra WHERE bra.businessResource.name = :resourceId")
    long countActionsByResourceIdentifier(@Param("resourceId") String resourceId);
}
