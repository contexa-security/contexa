package io.contexa.contexaiam.admin.web.center.dto;

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexaiam.domain.dto.ResourceSearchCriteria;
import lombok.Data;

import java.util.Locale;

@Data
public class PolicyResourceSearchRequest {
    private String keyword;
    private String resourceType;
    private String serviceOwner;
    private String status;

    public ResourceSearchCriteria toCriteria() {
        ResourceSearchCriteria criteria = new ResourceSearchCriteria();
        criteria.setKeyword(keyword);
        criteria.setResourceType(enumValue(ManagedResource.ResourceType.class, resourceType));
        criteria.setServiceOwner(serviceOwner);
        criteria.setStatus(enumValue(ManagedResource.Status.class, status));
        return criteria;
    }

    private static <E extends Enum<E>> E enumValue(Class<E> enumType, String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return Enum.valueOf(enumType, value.trim().toUpperCase(Locale.ROOT));
    }
}
