package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.business.BusinessResource;
import io.contexa.contexacommon.entity.business.BusinessResourceAction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * BusinessResource와 BusinessAction 간의 매핑 정보를 담고 있는
 * BusinessResourceAction 엔티티에 대한 데이터 접근 리포지토리.
 * 
 * 실무급 위험 평가를 위한 쿼리 메서드 추가
 */
@Repository
public interface BusinessResourceActionRepository extends JpaRepository<BusinessResourceAction, BusinessResourceAction.BusinessResourceActionId> {
    
    /**
     * 리소스 ID로 BusinessResource 조회
     */
    @Query("SELECT bra.businessResource FROM BusinessResourceAction bra WHERE bra.businessResource.name = :resourceId")
    Optional<BusinessResource> findByResourceIdentifier(@Param("resourceId") String resourceId);
    
    /**
     * 리소스별 일평균 접근 횟수 계산 (실제로는 AuditLog와 연계 필요)
     * 임시로 고정값 반환, 실제로는 복잡한 집계 쿼리 필요
     */
    @Query("SELECT 10.5 FROM BusinessResourceAction bra WHERE bra.businessResource.name = :resourceId")
    double getAverageAccessesPerDay(@Param("resourceId") String resourceId);
    
    /**
     * 리소스 타입 조회 (sensitivityLevel 대신 resourceType 사용)
     */
    @Query("SELECT br.resourceType FROM BusinessResource br WHERE br.name = :resourceId")
    Optional<String> getResourceSensitivityLevel(@Param("resourceId") String resourceId);
    
    /**
     * 리소스별 허용된 액션 수 조회
     */
    @Query("SELECT COUNT(bra) FROM BusinessResourceAction bra WHERE bra.businessResource.name = :resourceId")
    long countActionsByResourceIdentifier(@Param("resourceId") String resourceId);
}
