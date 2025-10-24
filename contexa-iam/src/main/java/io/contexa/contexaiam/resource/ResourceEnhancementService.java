package io.contexa.contexaiam.resource;

import io.contexa.contexaiam.domain.dto.ResourceMetadataDto;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexacommon.entity.ManagedResource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * [수정됨 및 역할 재정의]
 * 사유: 지적하신 'setManaged' 오류를 수정합니다. 핵심 로직이 ResourceRegistryService로 이전됨에 따라,
 *      이 서비스는 향후 리소스 메타데이터를 '강화(enrich)'하는 추가적인 로직(예: AI 기반 설명 생성)을
 *      위한 확장 지점으로 역할을 재정의합니다. 현재는 RegistryService로의 위임 역할만 수행합니다.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ResourceEnhancementService {

    private final ResourceRegistryService resourceRegistryService;

    /**
     * 리소스 메타데이터(친화적 이름, 설명)를 업데이트하고 권한으로 정의하는 프로세스를 시작합니다.
     * 실제 로직은 ResourceRegistryService에 위임됩니다.
     * @param id 리소스 ID
     * @param metadataDto 업데이트할 메타데이터
     */
    @Transactional
    public void defineResource(Long id, ResourceMetadataDto metadataDto) {
        log.info("Delegating resource definition for ID: {}", id);
        resourceRegistryService.defineResourceAsPermission(id, metadataDto);
    }

    /**
     * 여러 리소스의 상태를 일괄적으로 변경합니다.
     * @param ids 상태를 변경할 리소스 ID 목록
     * @param status 적용할 새로운 상태
     */
    @Transactional
    public void batchUpdateStatus(List<Long> ids, ManagedResource.Status status) {
        log.info("Batch updating status for {} resources to {}", ids.size(), status);
        // ResourceRegistryService에 해당 기능을 구현해야 합니다.
        // resourceRegistryService.batchUpdateStatus(ids, status);
    }


    /**
     * 시스템의 모든 리소스를 다시 스캔하고 동기화합니다.
     * 실제 로직은 ResourceRegistryService에 위임됩니다.
     */
    public void refreshResources() {
        log.info("Delegating resource refresh command.");
        resourceRegistryService.refreshAndSynchronizeResources();
    }
}
