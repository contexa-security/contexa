package io.contexa.demo.workspace.evidence.dto;

public record WorkspaceEvidenceStores(String baseline, String contexa, String security) {

    public String url(String role) {
        return switch (role) {
            case "baseline" -> baseline;
            case "contexa" -> contexa;
            case "security" -> security;
            default -> throw new IllegalArgumentException("Invalid evidence store role");
        };
    }
}
