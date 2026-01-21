package io.contexa.contexaiam.domain.dto;

import io.contexa.contexaiam.domain.entity.FunctionCatalog;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

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