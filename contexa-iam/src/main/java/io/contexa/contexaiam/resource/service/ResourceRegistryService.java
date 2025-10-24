package io.contexa.contexaiam.resource.service;

import io.contexa.contexaiam.domain.dto.ResourceManagementDto;
import io.contexa.contexaiam.domain.dto.ResourceMetadataDto;
import io.contexa.contexaiam.domain.dto.ResourceSearchCriteria;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Set;

public interface ResourceRegistryService {
    /**
     * [기존 refreshResources 역할 대체]
     * 시스템 시작 또는 관리자 요청 시, 모든 리소스를 재탐색하고 DB와 동기화합니다.
     * 새로 발견된 리소스는 'is_defined = false' 상태로 등록됩니다.
     */
    void refreshAndSynchronizeResources();

    /**
     * [신규 - 핵심 워크플로우 메서드]
     * 관리자가 워크벤치에서 정의한 리소스를 기반으로 실제 Permission을 생성/동기화합니다.
     * 이 메서드는 내부적으로 ManagedResource의 상태를 is_defined=true로 변경하고,
     * PermissionCatalogService를 호출하여 작업을 완료합니다.
     *
     * @param resourceId 정의할 ManagedResource의 ID
     * @param metadataDto 관리자가 입력한 친화적 이름, 설명 등
     * @return 생성 또는 업데이트된 Permission 엔티티
     */
    Permission defineResourceAsPermission(Long resourceId, ResourceMetadataDto metadataDto);

    /**
     * [기존 findResources 역할 유지]
     * 워크벤치 UI를 위한 리소스 목록을 조건에 따라 페이징하여 조회합니다.
     * @param searchCriteria 검색 조건 (is_defined, 키워드 등 포함)
     * @param pageable 페이징 정보
     * @return 페이징된 ManagedResource 목록
     */
    Page<ManagedResource> findResources(ResourceSearchCriteria searchCriteria, Pageable pageable);

    /**
     * [신규 또는 기존 updateResource 역할 대체]
     * 리소스의 관리 여부(워크벤치 표시 여부) 등 단순 메타데이터만 업데이트합니다.
     * 권한 생성과는 무관합니다.
     * @param resourceId 업데이트할 ManagedResource의 ID
     * @param managedDto 관리 여부 등
     */
    void updateResourceManagementStatus(Long resourceId, ResourceManagementDto managedDto); // ResourceManagementDto는 isManaged 필드만 가짐

    void excludeResourceFromManagement(Long resourceId);

    void restoreResourceToManagement(Long resourceId);

    Set<String> getAllServiceOwners();
    void batchUpdateStatus(List<Long> ids, ManagedResource.Status status);
}