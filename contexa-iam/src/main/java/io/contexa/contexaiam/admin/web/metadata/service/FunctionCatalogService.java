package io.contexa.contexaiam.admin.web.metadata.service;

import io.contexa.contexaiam.domain.dto.FunctionCatalogDto;
import io.contexa.contexaiam.domain.dto.FunctionCatalogUpdateDto;
import io.contexa.contexaiam.domain.dto.GroupedFunctionCatalogDto;
import io.contexa.contexaiam.domain.entity.FunctionCatalog;
import io.contexa.contexaiam.domain.entity.FunctionGroup;
import io.contexa.contexaiam.repository.FunctionCatalogRepository;
import io.contexa.contexaiam.repository.FunctionGroupRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class FunctionCatalogService {

    private final FunctionCatalogRepository functionCatalogRepository;
    private final FunctionGroupRepository functionGroupRepository;
    private final ModelMapper modelMapper;

    public List<FunctionCatalog> findUnconfirmedFunctions() {
        return functionCatalogRepository.findFunctionsByStatusWithDetails(FunctionCatalog.CatalogStatus.UNCONFIRMED);
    }

    public List<FunctionGroup> getAllFunctionGroups() {
        if (functionGroupRepository.count() == 0) {
            functionGroupRepository.save(FunctionGroup.builder().name("일반").build());
            functionGroupRepository.save(FunctionGroup.builder().name("사용자 관리").build());
        }
        return functionGroupRepository.findAll();
    }

    @Transactional
    public void confirmFunction(Long catalogId, Long groupId) {
        FunctionCatalog catalog = functionCatalogRepository.findById(catalogId)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 기능 카탈로그 ID: " + catalogId));
        FunctionGroup group = functionGroupRepository.findById(groupId)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 기능 그룹 ID: " + groupId));

        catalog.setStatus(FunctionCatalog.CatalogStatus.ACTIVE);
        catalog.setFunctionGroup(group);
        functionCatalogRepository.save(catalog);
        log.info("기능이 확인 및 등록되었습니다. [ID: {}, 이름: {}, 그룹: {}]", catalog.getId(), catalog.getFriendlyName(), group.getName());
    }

    

    
    public List<FunctionCatalogDto> getManageableCatalogs() {
        return functionCatalogRepository.findAllByStatusNotWithDetails(FunctionCatalog.CatalogStatus.UNCONFIRMED).stream()
                .map(this::convertToDto)
                .collect(Collectors.toList());
    }

    
    @Transactional
    public void updateCatalog(Long id, FunctionCatalogUpdateDto dto) {
        FunctionCatalog catalog = functionCatalogRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 기능 카탈로그 ID: " + id));
        FunctionGroup group = functionGroupRepository.findById(dto.getGroupId())
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 기능 그룹 ID: " + dto.getGroupId()));

        catalog.setFriendlyName(dto.getFriendlyName());
        catalog.setDescription(dto.getDescription());
        catalog.setStatus(dto.getStatus());
        catalog.setFunctionGroup(group);
        functionCatalogRepository.save(catalog);
    }

    
    @Transactional
    public void updateSingleStatus(Long catalogId, String status) {
        FunctionCatalog catalog = functionCatalogRepository.findById(catalogId)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 기능 카탈로그 ID: " + catalogId));
        FunctionCatalog.CatalogStatus newStatus = FunctionCatalog.CatalogStatus.valueOf(status.toUpperCase());
        catalog.setStatus(newStatus);
        functionCatalogRepository.save(catalog);
        log.info("카탈로그 ID {}의 상태가 {}로 변경되었습니다.", catalogId, newStatus);
    }

    
    public List<FunctionCatalog> findAllActiveFunctions() {
        
        return functionCatalogRepository.findFunctionsByStatusWithDetails(FunctionCatalog.CatalogStatus.ACTIVE);
    }

    
    public GroupedFunctionCatalogDto getGroupedCatalogs() {
        List<FunctionCatalog> allCatalogs = functionCatalogRepository.findAllWithDetails();

        Map<FunctionCatalog.CatalogStatus, List<FunctionCatalogDto>> grouped = allCatalogs.stream()
                .map(this::convertToDto)
                .collect(Collectors.groupingBy(FunctionCatalogDto::getStatus));

        return new GroupedFunctionCatalogDto(grouped);
    }

    
    @Transactional
    public void confirmBatch(List<Map<String, Long>> payload) {
        for (Map<String, Long> item : payload) {
            Long catalogId = item.get("catalogId");
            Long groupId = item.get("groupId");
            confirmFunction(catalogId, groupId); 
        }
    }

    
    @Transactional
    public void batchUpdateStatus(List<Long> ids, String status) {
        FunctionCatalog.CatalogStatus newStatus = FunctionCatalog.CatalogStatus.valueOf(status.toUpperCase());
        List<FunctionCatalog> catalogs = functionCatalogRepository.findAllById(ids);
        catalogs.forEach(catalog -> catalog.setStatus(newStatus));
        functionCatalogRepository.saveAll(catalogs);
    }

    private FunctionCatalogDto convertToDto(FunctionCatalog catalog) {
        if (catalog == null) {
            return null;
        }

        FunctionCatalogDto dto = new FunctionCatalogDto();

        
        dto.setId(catalog.getId());
        dto.setFriendlyName(catalog.getFriendlyName());
        dto.setDescription(catalog.getDescription());
        dto.setStatus(catalog.getStatus());

        
        if (catalog.getManagedResource() != null) {
            dto.setResourceIdentifier(catalog.getManagedResource().getResourceIdentifier());
            dto.setResourceType(catalog.getManagedResource().getResourceType().name());
            dto.setOwner(catalog.getManagedResource().getServiceOwner());
            dto.setParameterTypes(catalog.getManagedResource().getParameterTypes());
            dto.setReturnType(catalog.getManagedResource().getReturnType());
        }

        
        if (catalog.getFunctionGroup() != null) {
            dto.setFunctionGroupName(catalog.getFunctionGroup().getName());
        } else {
            dto.setFunctionGroupName("미지정");
        }

        return dto;
    }

    
}