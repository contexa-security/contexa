package io.contexa.contexaiam.admin.web.menu.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class AdminMenuDtos {

    private AdminMenuDtos() {
    }

    private static Long parseRequiredLong(Object value, String fieldName) {
        if (value == null || String.valueOf(value).isBlank()) {
            throw new IllegalArgumentException(fieldName + " is required");
        }
        try {
            return Long.valueOf(String.valueOf(value));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(fieldName + " must be a number", e);
        }
    }

    private static Long parseOptionalLong(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Long.valueOf(value);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(fieldName + " must be a number", e);
        }
    }

    private static int parseRequiredInt(Object value, String fieldName) {
        if (value == null || String.valueOf(value).isBlank()) {
            throw new IllegalArgumentException(fieldName + " is required");
        }
        try {
            return Integer.parseInt(String.valueOf(value));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(fieldName + " must be a number", e);
        }
    }

    public record AdminMenuPageModel(
            List<AdminMenuView> menus,
            Set<Long> parentIds,
            List<AdminRoleOptionView> allRoles
    ) {
    }

    public record AdminMenuView(
            Long id,
            String name,
            String url,
            String icon,
            Long parentId,
            int menuOrder,
            boolean enabled,
            String menuType,
            String dataPage,
            List<AdminMenuRoleView> roles
    ) {
        public Long getId() { return id; }
        public String getName() { return name; }
        public String getUrl() { return url; }
        public String getIcon() { return icon; }
        public Long getParentId() { return parentId; }
        public int getMenuOrder() { return menuOrder; }
        public boolean isEnabled() { return enabled; }
        public String getMenuType() { return menuType; }
        public String getDataPage() { return dataPage; }
        public List<AdminMenuRoleView> getRoles() { return roles; }
    }

    public record AdminMenuRoleView(String roleName) {
        public String getRoleName() { return roleName; }
    }

    public record AdminRoleOptionView(String roleName) {
        public String getRoleName() { return roleName; }
    }

    public record AdminMenuResponse(
            Long id,
            String name,
            String url,
            String icon,
            Long parentId,
            int menuOrder,
            String menuType,
            String dataPage,
            boolean enabled,
            List<String> roles
    ) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record AdminMenuActionResponse(
            boolean success,
            Long id,
            String error
    ) {
        public static AdminMenuActionResponse ok() {
            return new AdminMenuActionResponse(true, null, null);
        }

        public static AdminMenuActionResponse created(Long id) {
            return new AdminMenuActionResponse(true, id, null);
        }

        public static AdminMenuActionResponse error(String error) {
            return new AdminMenuActionResponse(false, null, error);
        }
    }

    public record AdminMenuRolesRequest(List<String> roles) {
        public List<String> rolesOrEmpty() {
            return roles != null ? roles : List.of();
        }
    }

    public record AdminMenuOrderRequest(String id, String order) {
        public Long menuId() {
            return parseRequiredLong(id, "id");
        }

        public int menuOrder() {
            return parseRequiredInt(order, "order");
        }
    }

    public static class AdminMenuSaveRequest {
        private final Set<String> presentFields = new HashSet<>();
        private String name;
        private String url;
        private String icon;
        private String dataPage;
        private String menuType;
        private String parentId;
        private String menuOrder;
        private String enabled;

        public String getName() { return name; }
        public String getUrl() { return url; }
        public String getIcon() { return icon; }
        public String getDataPage() { return dataPage; }
        public String getMenuType() { return menuType; }
        public String getParentId() { return parentId; }
        public String getMenuOrder() { return menuOrder; }
        public String getEnabled() { return enabled; }

        public void setName(String name) {
            presentFields.add("name");
            this.name = name;
        }

        public void setUrl(String url) {
            presentFields.add("url");
            this.url = url;
        }

        public void setIcon(String icon) {
            presentFields.add("icon");
            this.icon = icon;
        }

        public void setDataPage(String dataPage) {
            presentFields.add("dataPage");
            this.dataPage = dataPage;
        }

        public void setMenuType(String menuType) {
            presentFields.add("menuType");
            this.menuType = menuType;
        }

        public void setParentId(String parentId) {
            presentFields.add("parentId");
            this.parentId = parentId;
        }

        public void setMenuOrder(String menuOrder) {
            presentFields.add("menuOrder");
            this.menuOrder = menuOrder;
        }

        public void setEnabled(String enabled) {
            presentFields.add("enabled");
            this.enabled = enabled;
        }

        @JsonIgnore
        public boolean has(String field) {
            return presentFields.contains(field);
        }

        @JsonIgnore
        public String valueOrDefault(String field, String defaultValue) {
            return switch (field) {
                case "name" -> name != null ? name : defaultValue;
                case "icon" -> icon != null ? icon : defaultValue;
                case "menuType" -> menuType != null ? menuType : defaultValue;
                case "menuOrder" -> menuOrder != null ? menuOrder : defaultValue;
                default -> defaultValue;
            };
        }

        @JsonIgnore
        public Long parentIdAsLong() {
            return parseOptionalLong(parentId, "parentId");
        }

        @JsonIgnore
        public int menuOrderOrDefault(int defaultValue) {
            return parseRequiredInt(valueOrDefault("menuOrder", String.valueOf(defaultValue)), "menuOrder");
        }

        @JsonIgnore
        public int menuOrderAsInt() {
            return parseRequiredInt(menuOrder, "menuOrder");
        }
    }
}
