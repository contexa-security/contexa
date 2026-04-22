package io.contexa.contexaiam.admin.web.auth.dto;

public final class RoleHierarchyDtos {

    private RoleHierarchyDtos() {
    }

    public record ActiveHierarchyView(Long id, String description, String hierarchyString) {

        public ActiveHierarchyView {
            description = description != null ? description : "";
            hierarchyString = hierarchyString != null ? hierarchyString : "";
        }

        public Long getId() {
            return id;
        }

        public String getDescription() {
            return description;
        }

        public String getHierarchyString() {
            return hierarchyString;
        }
    }
}
