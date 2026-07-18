package io.contexa.autoconfigure.iam.admin;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

@ConfigurationProperties("contexa.pqa.routes")
public class PromptQualityRouteProperties {

    public static final String DEFAULT_OFFICIAL_API_ROOT = "/contexa/admin/api/prompt-quality";
    public static final String DEFAULT_ENTERPRISE_API_ROOT = "/contexa/admin/api/enterprise/prompt-quality";
    public static final String DEFAULT_ENTERPRISE_VERIFICATION_RUNTIME_RUNS_PATH =
            "/verification/runtime-runs";

    private String officialApiRoot = DEFAULT_OFFICIAL_API_ROOT;
    private String enterpriseApiRoot = DEFAULT_ENTERPRISE_API_ROOT;
    private String enterpriseVerificationRuntimeRunsPath =
            DEFAULT_ENTERPRISE_VERIFICATION_RUNTIME_RUNS_PATH;

    public String getOfficialApiRoot() {
        return officialApiRoot;
    }

    public void setOfficialApiRoot(String officialApiRoot) {
        this.officialApiRoot = normalizeRoot("officialApiRoot", officialApiRoot);
    }

    public String getEnterpriseApiRoot() {
        return enterpriseApiRoot;
    }

    public void setEnterpriseApiRoot(String enterpriseApiRoot) {
        this.enterpriseApiRoot = normalizeRoot("enterpriseApiRoot", enterpriseApiRoot);
    }

    public String getEnterpriseVerificationRuntimeRunsPath() {
        return enterpriseVerificationRuntimeRunsPath;
    }

    public void setEnterpriseVerificationRuntimeRunsPath(String path) {
        this.enterpriseVerificationRuntimeRunsPath = normalizeRoot(
                "enterpriseVerificationRuntimeRunsPath", path);
    }

    private String normalizeRoot(String field, String value) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException("contexa.pqa.routes." + field + " must not be blank.");
        }
        String normalized = value.trim();
        if (!normalized.startsWith("/")) {
            throw new IllegalArgumentException("contexa.pqa.routes." + field + " must start with '/'.");
        }
        while (normalized.length() > 1 && normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }
}
