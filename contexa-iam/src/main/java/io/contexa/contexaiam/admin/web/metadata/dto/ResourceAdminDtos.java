package io.contexa.contexaiam.admin.web.metadata.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.springframework.data.domain.Page;

import java.time.LocalDateTime;
import java.util.Set;

public final class ResourceAdminDtos {

    private ResourceAdminDtos() {
    }

    public record ResourceWorkbenchPageModel(
            Page<ResourceWorkbenchResourceView> resourcePage,
            Set<String> serviceOwners,
            ResourceSearchForm criteria
    ) {
    }

    public record ResourceWorkbenchResourceView(
            Long id,
            String resourceIdentifier,
            EnumNameValue resourceType,
            EnumNameValue httpMethod,
            String friendlyName,
            String description,
            String serviceOwner,
            String parameterTypes,
            String returnType,
            String apiDocsUrl,
            String sourceCodeLocation,
            String availableContextVariables,
            EnumNameValue status,
            ResourcePermissionView permission,
            LocalDateTime createdAt,
            LocalDateTime updatedAt
    ) {
        public Long getId() { return id; }
        public String getResourceIdentifier() { return resourceIdentifier; }
        public EnumNameValue getResourceType() { return resourceType; }
        public EnumNameValue getHttpMethod() { return httpMethod; }
        public String getFriendlyName() { return friendlyName; }
        public String getDescription() { return description; }
        public String getServiceOwner() { return serviceOwner; }
        public String getParameterTypes() { return parameterTypes; }
        public String getReturnType() { return returnType; }
        public String getApiDocsUrl() { return apiDocsUrl; }
        public String getSourceCodeLocation() { return sourceCodeLocation; }
        public String getAvailableContextVariables() { return availableContextVariables; }
        public EnumNameValue getStatus() { return status; }
        public ResourcePermissionView getPermission() { return permission; }
        public LocalDateTime getCreatedAt() { return createdAt; }
        public LocalDateTime getUpdatedAt() { return updatedAt; }
    }

    public record EnumNameValue(String value) {
        public String name() {
            return value;
        }

        @Override
        public String toString() {
            return value;
        }
    }

    public record ResourcePermissionView(
            Long id,
            String name,
            String friendlyName,
            String description
    ) {
        public Long getId() { return id; }
        public String getName() { return name; }
        public String getFriendlyName() { return friendlyName; }
        public String getDescription() { return description; }
    }

    public static class ResourceSearchForm {
        private String keyword;
        private String resourceType;
        private String serviceOwner;
        private String status;

        public String getKeyword() { return keyword; }
        public void setKeyword(String keyword) { this.keyword = keyword; }
        public String getResourceType() { return resourceType; }
        public void setResourceType(String resourceType) { this.resourceType = resourceType; }
        public String getServiceOwner() { return serviceOwner; }
        public void setServiceOwner(String serviceOwner) { this.serviceOwner = serviceOwner; }
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
    }

    public static class ResourceMetadataForm {
        private String friendlyName;
        private String description;
        private String serviceOwner;

        public String getFriendlyName() { return friendlyName; }
        public void setFriendlyName(String friendlyName) { this.friendlyName = friendlyName; }
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
        public String getServiceOwner() { return serviceOwner; }
        public void setServiceOwner(String serviceOwner) { this.serviceOwner = serviceOwner; }
    }

    public static class ResourceManagementForm {
        private String status;

        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ResourceDefineResponse(
            String message,
            Long permissionId,
            String permissionName
    ) {
        public static ResourceDefineResponse error(String message) {
            return new ResourceDefineResponse(message, null, null);
        }
    }

    public record ResourceBatchDefineRequest(
            Long resourceId,
            String friendlyName,
            String description
    ) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ResourceBatchDefineResult(
            Long resourceId,
            Long permissionId,
            String permissionName,
            Boolean skipped,
            String error
    ) {
        public static ResourceBatchDefineResult missingResourceId() {
            return new ResourceBatchDefineResult(null, null, null, true, "resourceId is required");
        }

        public static ResourceBatchDefineResult skipped(Long resourceId, Long permissionId, String permissionName) {
            return new ResourceBatchDefineResult(resourceId, permissionId, permissionName, true, null);
        }

        public static ResourceBatchDefineResult created(Long resourceId, Long permissionId, String permissionName) {
            return new ResourceBatchDefineResult(resourceId, permissionId, permissionName, false, null);
        }

        public static ResourceBatchDefineResult error(Long resourceId, String error) {
            return new ResourceBatchDefineResult(resourceId, null, null, true, error);
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ResourceStatusResponse(
            String message,
            Long resourceId,
            String newStatus
    ) {
        public static ResourceStatusResponse error(String message) {
            return new ResourceStatusResponse(message, null, null);
        }
    }
}
