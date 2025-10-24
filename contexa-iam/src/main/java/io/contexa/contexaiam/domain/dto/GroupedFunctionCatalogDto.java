package io.contexa.contexaiam.domain.dto;

import io.contexa.contexaiam.domain.entity.FunctionCatalog;
import lombok.Getter;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * permissions-catalog.html 뷰에서 상태별로 탭을 나누어 표시하기 위한 전용 DTO
 */
@Getter
public class GroupedFunctionCatalogDto {

    private final List<FunctionCatalogDto> unconfirmed;
    private final List<FunctionCatalogDto> active;
    private final List<FunctionCatalogDto> inactive;

    public GroupedFunctionCatalogDto(Map<FunctionCatalog.CatalogStatus, List<FunctionCatalogDto>> groupedCatalogs) {
        this.unconfirmed = groupedCatalogs.getOrDefault(FunctionCatalog.CatalogStatus.UNCONFIRMED, Collections.emptyList());
        this.active = groupedCatalogs.getOrDefault(FunctionCatalog.CatalogStatus.ACTIVE, Collections.emptyList());
        this.inactive = groupedCatalogs.getOrDefault(FunctionCatalog.CatalogStatus.INACTIVE, Collections.emptyList());
    }
}
