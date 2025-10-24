package io.contexa.contexaiam.domain.dto;

import io.contexa.contexaiam.domain.entity.FunctionCatalog;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * '기능 카탈로그 관리' 화면에 목록을 표시하기 위한 DTO
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class FunctionCatalogDto {
    private Long id;
    private String friendlyName;
    private String description;
    private FunctionCatalog.CatalogStatus status;
    private String functionGroupName;
    private String resourceIdentifier;
    private String resourceType;
    private String owner;
    private String parameterTypes;
    private String returnType;
}