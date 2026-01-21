package io.contexa.contexaiam.domain.dto;
import io.contexa.contexaiam.domain.entity.FunctionCatalog;
import lombok.Data;

@Data
public class FunctionCatalogUpdateDto {
    private String friendlyName;
    private String description;
    private FunctionCatalog.CatalogStatus status;
    private Long groupId;
}