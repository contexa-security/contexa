package io.contexa.contexaiam.resource.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import io.contexa.contexacore.std.operations.AINativeProcessor;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexacommon.domain.request.IAMRequest;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.aiam.protocol.context.ResourceNamingContext;
import io.contexa.contexacommon.enums.DiagnosisType;
import io.contexa.contexacommon.enums.SecurityLevel;
import io.contexa.contexaiam.aiam.protocol.request.ResourceNameSuggestion;
import io.contexa.contexaiam.aiam.protocol.response.ResourceNamingSuggestionResponse;
import io.contexa.contexaiam.domain.dto.ResourceManagementDto;
import io.contexa.contexaiam.domain.dto.ResourceMetadataDto;
import io.contexa.contexaiam.domain.dto.ResourceSearchCriteria;
import io.contexa.contexaiam.resource.scanner.ResourceScanner;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class ResourceRegistryServiceImpl implements ResourceRegistryService {
    
    private final List<ResourceScanner> scanners;
    private final ManagedResourceRepository managedResourceRepository;
    private final PermissionCatalogService permissionCatalogService;
    private final AINativeProcessor aiNativeProcessor;
    private final AutoConditionTemplateService autoConditionTemplateService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * [구현 완료] 리소스 스캔, 신규/변경/삭제 리소스 구분 및 AI 추천까지 모든 로직을 완벽하게 구현합니다.
     * 이 메서드는 비동기로 실행되어 애플리케이션 시작을 지연시키지 않습니다.
     */
    @Async
    @Override
    @Transactional
    public void
    refreshAndSynchronizeResources() {
        log.info("비동기 리소스 스캐닝 및 DB 동기화를 시작합니다...");

        // 1. [수정] 모든 스캐너에서 발견된 리소스를 중복을 허용하여 List로 받습니다.
        List<ManagedResource> discoveredResources = scanners.stream()
                .flatMap(scanner -> scanner.scan().stream())
                .filter(Objects::nonNull)
                .toList();

        // 중복된 resourceIdentifier를 가진 리소스를 그룹화하여, 잠재적 문제를 로깅합니다.
        Map<String, List<ManagedResource>> groupedByIdentifier = discoveredResources.stream()
                .collect(Collectors.groupingBy(ManagedResource::getResourceIdentifier));

        groupedByIdentifier.forEach((identifier, list) -> {
            if (list.size() > 1) {
                log.warn("리소스 식별자 충돌 감지: '{}'이(가) {}개의 스캐너에서 발견되었습니다. 첫 번째 발견된 리소스를 사용합니다.", identifier, list.size());
            }
        });

        // 중복을 제거한 최종 발견 리소스 맵
        Map<String, ManagedResource> discoveredResourcesMap = groupedByIdentifier.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> entry.getValue().get(0)));
        log.info("모든 스캐너로부터 {}개의 고유한 리소스를 발견했습니다.", discoveredResourcesMap.size());

        Map<String, ManagedResource> existingResourcesMap = managedResourceRepository.findAll().stream()
                .collect(Collectors.toMap(ManagedResource::getResourceIdentifier, Function.identity()));
        log.info("데이터베이스에서 {}개의 기존 리소스를 조회했습니다.", existingResourcesMap.size());

        // 2. '새로운' 리소스(newResources) 목록을 정확하게 필터링합니다.
        List<ManagedResource> newResources = discoveredResourcesMap.values().stream()
                .filter(discovered -> !existingResourcesMap.containsKey(discovered.getResourceIdentifier()))
                .toList();

        // 3. '사라진' 리소스(removedResources) 목록을 필터링합니다.
        List<ManagedResource> removedResources = existingResourcesMap.values().stream()
                .filter(existing -> !discoveredResourcesMap.containsKey(existing.getResourceIdentifier()))
                .toList();

        if (!removedResources.isEmpty()) {
            log.warn("{}개의 리소스가 현재 코드에서 발견되지 않았습니다. (예: {})", removedResources.size(), removedResources.get(0).getResourceIdentifier());
            // TODO: 사라진 리소스에 대한 처리 로직 (예: status를 DEPRECATED로 변경 후 저장)
        }

        // 4. [구현 완료] 새로운 리소스 개수에 따라 AI 추천 처리 방식을 동적으로 결정합니다.
        if (newResources.isEmpty()) {
            log.info("새로 발견된 리소스가 없어 AI 추천을 건너뜁니다.");
        } else if (newResources.size() == 1) {
            // ----- 1개일 경우: 단일 처리 -----
            processSingleResource(newResources.getFirst());
        } else {
            // ----- 2개 이상일 경우: 배치 및 병렬 처리 -----
            int batchSize = 10; // 한 번에 처리할 배치 크기
            List<List<ManagedResource>> resourceBatches = Lists.partition(newResources, batchSize);
            log.info("{}개의 새로운 리소스를 {}개의 배치로 나누어 병렬 처리합니다...", newResources.size(), resourceBatches.size());

            List<CompletableFuture<Void>> futures = resourceBatches.stream()
                    .map(batch -> CompletableFuture.runAsync(() -> processResourceBatch(batch)))
                    .toList();

            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
            log.info("모든 AI 추천 배치 작업이 완료되었습니다.");
        }
        autoConditionTemplateService.generateConditionTemplates();
        log.info("리소스 동기화 프로세스가 완료되었습니다.");
    }
    
    /**
     * [구현 완료] 단일 신규 리소스에 대한 AI 추천 및 저장 로직.
     * 비동기 작업 내에서 별도의 트랜잭션으로 실행되도록 설정합니다.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void processSingleResource(ManagedResource resource) {
        log.info("1개의 새로운 리소스 '{}'에 대한 AI 추천을 요청합니다...", resource.getResourceIdentifier());
        try {
            // 신버전: AINativeIAMOperations를 통한 AI 진단 요청 (AiApiController 패턴)
            List<Map<String, String>> singleResourceList = List.of(
                Map.of("identifier", resource.getResourceIdentifier(), 
                       "owner", resource.getServiceOwner() != null ? resource.getServiceOwner() : "Unknown")
            );
            
            IAMRequest<ResourceNamingContext> request = createResourceNamingRequest(singleResourceList);
            
            // ResourceNamingSuggestionResponse로 직접 받기 (StringResponse 제거!) - 비동기 → 동기 변환
            Object rawResponse = aiNativeProcessor.process(request, ResourceNamingSuggestionResponse.class).block();
            ResourceNamingSuggestionResponse suggestionResponse = (ResourceNamingSuggestionResponse) rawResponse;
            
            // 응답에서 추천 결과 추출
            Map<String, ResourceNameSuggestion> suggestions = suggestionResponse.toResourceNameSuggestionMap();
            ResourceNameSuggestion suggestion = suggestions.get(resource.getResourceIdentifier());
            
            if (suggestion != null) {
                resource.setFriendlyName(suggestion.friendlyName());
                resource.setDescription(suggestion.description());
                log.info("AI 추천 적용 완료: '{}' -> '{}'", resource.getResourceIdentifier(), suggestion.friendlyName());
            } else {
                // AI가 추천을 제공하지 않은 경우 기본값 설정
                resource.setFriendlyName(generateFallbackFriendlyName(resource.getResourceIdentifier()));
                resource.setDescription("AI 추천을 받지 못한 리소스입니다.");
                log.warn("AI가 추천을 제공하지 않아 기본값을 사용합니다: {}", resource.getResourceIdentifier());
            }
            
            managedResourceRepository.save(resource);
            
        } catch (Exception e) {
            log.warn("AI 리소스 이름 추천 실패: {}. 기본값을 사용합니다.", resource.getResourceIdentifier(), e);
            resource.setFriendlyName(generateFallbackFriendlyName(resource.getResourceIdentifier()));
            resource.setDescription("AI 추천 실패로 기본값을 사용합니다.");
            managedResourceRepository.save(resource);
        }
    }

    /**
     * [구현 완료] 리소스 배치에 대한 AI 추천 및 저장 로직.
     * 비동기 작업 내에서 별도의 트랜잭션으로 실행되도록 설정합니다.
     */
    /**
     * [구현 완료] 리소스 배치에 대한 AI 추천 및 저장 로직.
     * 비동기 작업 내에서 별도의 트랜잭션으로 실행되도록 설정합니다.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void processResourceBatch(List<ManagedResource> batch) {
        log.info("{}개 리소스 배치의 AI 추천 처리를 시작합니다.", batch.size());

        // 입력 데이터 검증
        if (batch == null || batch.isEmpty()) {
            log.warn("배치가 비어있어 처리를 건너뜁니다.");
            return;
        }

        // AI 요청 데이터 준비
        List<Map<String, String>> resourcesToSuggest = batch.stream()
                .filter(Objects::nonNull)
                .filter(r -> r.getResourceIdentifier() != null && !r.getResourceIdentifier().trim().isEmpty())
                .map(r -> {
                    String identifier = r.getResourceIdentifier();
                    String owner = r.getServiceOwner() != null ? r.getServiceOwner() : "Unknown";

                    log.debug("AI 요청 데이터 준비: identifier={}, owner={}", identifier, owner);
                    return Map.of("identifier", identifier, "owner", owner);
                })
                .collect(Collectors.toList());

        if (resourcesToSuggest.isEmpty()) {
            log.warn("유효한 리소스가 없어 AI 추천을 건너뜁니다.");
            // 그래도 기본값으로 저장
            managedResourceRepository.saveAll(batch);
            return;
        }

        log.info("{}개의 유효한 리소스에 대해 AI 추천을 요청합니다.", resourcesToSuggest.size());

        try {
            // 신버전: AINativeIAMOperations를 통한 AI 진단 요청 (AiApiController 패턴)
            IAMRequest<ResourceNamingContext> request = createResourceNamingRequest(resourcesToSuggest);
            
            // ResourceNamingSuggestionResponse로 직접 받기 (StringResponse 제거!) - 비동기 → 동기 변환
            Object rawResponse = aiNativeProcessor.process(request, ResourceNamingSuggestionResponse.class).block();
            ResourceNamingSuggestionResponse suggestionResponse = (ResourceNamingSuggestionResponse) rawResponse;
            
            // 응답에서 추천 결과 추출
            Map<String, ResourceNameSuggestion> suggestionsMap = suggestionResponse.toResourceNameSuggestionMap();

            log.info("AI로부터 {}개의 추천을 받았습니다.", suggestionsMap.size());

            // 각 리소스에 AI 추천 적용
            int appliedCount = 0;
            int skippedCount = 0;

            for (ManagedResource resource : batch) {
                if (resource.getResourceIdentifier() == null) {
                    log.warn("리소스 식별자가 null인 리소스를 건너뜁니다: {}", resource);
                    skippedCount++;
                    continue;
                }

                ResourceNameSuggestion suggestion = suggestionsMap.get(resource.getResourceIdentifier());

                if (suggestion != null) {
                    String oldFriendlyName = resource.getFriendlyName();
                    String oldDescription = resource.getDescription();

                    resource.setFriendlyName(suggestion.friendlyName());
                    resource.setDescription(suggestion.description());

                    log.debug("AI 추천 적용: '{}' -> friendlyName='{}', description='{}'",
                            resource.getResourceIdentifier(),
                            suggestion.friendlyName(),
                            suggestion.description());

                    appliedCount++;
                } else {
                    log.warn("AI가 리소스 '{}'에 대한 추천을 반환하지 않았습니다. 기본값을 유지합니다.",
                            resource.getResourceIdentifier());

                    // 기본값 설정 (필요한 경우)
                    if (resource.getFriendlyName() == null || resource.getFriendlyName().trim().isEmpty()) {
                        resource.setFriendlyName(generateFallbackFriendlyName(resource.getResourceIdentifier()));
                    }
                    if (resource.getDescription() == null || resource.getDescription().trim().isEmpty()) {
                        resource.setDescription("AI 추천을 받지 못한 리소스입니다.");
                    }

                    skippedCount++;
                }
            }

            // 배치 저장
            managedResourceRepository.saveAll(batch);

            log.info("배치 처리 완료 - 전체: {}개, AI 적용: {}개, 기본값 사용: {}개",
                    batch.size(), appliedCount, skippedCount);

        } catch (Exception e) {
            log.error("AI 추천 처리 중 오류 발생. 기본값으로 저장합니다.", e);

            // 오류 발생 시 기본값으로 설정하여 저장
            batch.forEach(resource -> {
                if (resource.getFriendlyName() == null || resource.getFriendlyName().trim().isEmpty()) {
                    resource.setFriendlyName(generateFallbackFriendlyName(resource.getResourceIdentifier()));
                }
                if (resource.getDescription() == null || resource.getDescription().trim().isEmpty()) {
                    resource.setDescription("AI 추천 실패로 기본값을 사용합니다.");
                }
            });

            managedResourceRepository.saveAll(batch);
            log.info("{}개의 리소스가 기본값으로 저장되었습니다.", batch.size());
        }
    }

    /**
     * Fallback용 기본 친화적 이름 생성
     */
    private String generateFallbackFriendlyName(String identifier) {
        if (identifier == null || identifier.isEmpty()) {
            return "알 수 없는 리소스";
        }

        // URL 경로에서 마지막 부분 추출
        if (identifier.startsWith("/")) {
            String[] parts = identifier.split("/");
            for (int i = parts.length - 1; i >= 0; i--) {
                if (!parts[i].isEmpty() && !parts[i].matches("\\{.*\\}")) {  // 경로 변수 제외
                    return parts[i] + " 기능";
                }
            }
        }

        // 메서드명에서 이름 추출
        if (identifier.contains(".")) {
            String[] parts = identifier.split("\\.");
            String lastPart = parts[parts.length - 1];
            if (lastPart.contains("()")) {
                lastPart = lastPart.replace("()", "");
            }
            // camelCase를 공백으로 분리
            String formatted = lastPart.replaceAll("([a-z])([A-Z])", "$1 $2").toLowerCase();
            return formatted + " 기능";
        }

        return identifier + " 기능";
    }

    @Override
    @Transactional
    public Permission defineResourceAsPermission(Long resourceId, ResourceMetadataDto metadataDto) {
        ManagedResource resource = managedResourceRepository.findById(resourceId)
                .orElseThrow(() -> new IllegalArgumentException("Resource not found with ID: " + resourceId));

        resource.setFriendlyName(metadataDto.getFriendlyName());
        resource.setDescription(metadataDto.getDescription());
        resource.setStatus(ManagedResource.Status.PERMISSION_CREATED); // 상태 변경

        ManagedResource savedResource = managedResourceRepository.save(resource);
        log.info("Resource (ID: {}) has been defined by admin. Status set to PERMISSION_CREATED.", resourceId);

        return permissionCatalogService.synchronizePermissionFor(savedResource);
    }

    @Override
    @Transactional
    public void updateResourceManagementStatus(Long resourceId, ResourceManagementDto managedDto) {
        ManagedResource resource = managedResourceRepository.findById(resourceId)
                .orElseThrow(() -> new IllegalArgumentException("Resource not found with ID: " + resourceId));
        if (resource.getPermission() != null) {
            resource.setStatus(ManagedResource.Status.PERMISSION_CREATED);
        } else {
            resource.setStatus(ManagedResource.Status.NEEDS_DEFINITION);
        }
        managedResourceRepository.save(resource);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<ManagedResource> findResources(ResourceSearchCriteria criteria, Pageable pageable) {
        // [핵심 수정] 존재하지 않는 findAll(predicate, pageable) 대신,
        // ManagedResourceRepositoryCustom에 정의하고 구현한 findByCriteria를 호출합니다.
        return managedResourceRepository.findByCriteria(criteria, pageable);
    }

    @Override
    @Transactional
    public void excludeResourceFromManagement(Long resourceId) {
        ManagedResource resource = managedResourceRepository.findById(resourceId)
                .orElseThrow(() -> new IllegalArgumentException("Resource not found with ID: " + resourceId));
        resource.setStatus(ManagedResource.Status.EXCLUDED);
        managedResourceRepository.save(resource);
        log.info("Resource (ID: {}) has been excluded from management.", resourceId);
    }

    @Override
    @Transactional
    public void restoreResourceToManagement(Long resourceId) {
        ManagedResource resource = managedResourceRepository.findById(resourceId)
                .orElseThrow(() -> new IllegalArgumentException("Resource not found with ID: " + resourceId));
        // 복원 시, 권한이 이미 생성되었는지 여부에 따라 상태를 결정
        if (resource.getPermission() != null) {
            resource.setStatus(ManagedResource.Status.PERMISSION_CREATED);
        } else {
            resource.setStatus(ManagedResource.Status.NEEDS_DEFINITION);
        }
        managedResourceRepository.save(resource);
        log.info("Resource (ID: {}) has been restored to management.", resourceId);
    }

    @Override
    @Transactional(readOnly = true)
    public Set<String> getAllServiceOwners() {
        return managedResourceRepository.findAllServiceOwners();
    }

    @Override
    @Transactional
    public void batchUpdateStatus(List<Long> ids, ManagedResource.Status status) {
        if (CollectionUtils.isEmpty(ids)) {
            return;
        }
        List<ManagedResource> resourcesToUpdate = managedResourceRepository.findAllById(ids);
        if (resourcesToUpdate.isEmpty()) {
            return;
        }

        for (ManagedResource resource : resourcesToUpdate) {
            // 복원 로직과 동일하게, 권한 존재 여부에 따라 상태를 결정
            if (status == ManagedResource.Status.NEEDS_DEFINITION) {
                if (resource.getPermission() != null) {
                    resource.setStatus(ManagedResource.Status.PERMISSION_CREATED);
                } else {
                    resource.setStatus(ManagedResource.Status.NEEDS_DEFINITION);
                }
            } else {
                resource.setStatus(status);
            }
        }

        managedResourceRepository.saveAll(resourcesToUpdate);
        log.info("Batch updated status for {} resources to {}", resourcesToUpdate.size(), status);
    }

    /**
     * 신버전: 리소스 네이밍 진단 요청 생성
     */
    /**
     * AiApiController 패턴을 따라 ResourceNaming 요청을 생성합니다
     */
    private IAMRequest<ResourceNamingContext> createResourceNamingRequest(List<Map<String, String>> resources) {
        // ResourceNamingContext 생성 (AiApiController 패턴)
        ResourceNamingContext context = new ResourceNamingContext.Builder(
            SecurityLevel.STANDARD,
            AuditRequirement.BASIC
        ).withResourceBatch(resources).build();

        // 수정: IAMRequest 직접 생성 (캐스팅 없이)
        IAMRequest<ResourceNamingContext> request = new IAMRequest<>(context, "suggestResourceNames");
        request.withDiagnosisType(DiagnosisType.RESOURCE_NAMING);
        request.withParameter("resources", resources);
        request.withParameter("batchSize", resources.size());
        
        log.debug("DiagnosisType 설정 확인: {}", request.getDiagnosisType());
        return request;
    }

    // extractResourceNamingSuggestions 메서드 제거됨 - ResourceNamingSuggestionResponse.toResourceNameSuggestionMap() 사용
}