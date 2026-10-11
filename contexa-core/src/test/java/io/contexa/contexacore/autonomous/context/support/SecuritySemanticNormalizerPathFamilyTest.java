package io.contexa.contexacore.autonomous.context.support;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W2-2: a path family names a kind of request, not one instance. The host's URL template is the family when it gave
 * one; otherwise identifier segments of the request path become {id}, so reading another document is not a new path.
 */
class SecuritySemanticNormalizerPathFamilyTest {

    @Test
    void theHostsUrlTemplateIsThePathFamilyKeptWhole() {
        Map<String, Object> metadata = Map.of(
                "protectableResourceUrl", "/api/projects/{projectKey}/exports/async",
                "resourceUrlTemplate", "/api/other/{x}");

        assertThat(SecuritySemanticNormalizer.pathFamilyOf(metadata, "/api/projects/GB-500/exports/async?items=4831"))
                .isEqualTo("/api/projects/{projectKey}/exports/async");
        assertThat(SecuritySemanticNormalizer.pathFamilyOf(
                Map.of("resourceUrlTemplate", "/api/documents/{documentKey}"), "/api/documents/HX-310-DWG-00001"))
                .isEqualTo("/api/documents/{documentKey}");
    }

    @Test
    void withoutATemplateIdentifierSegmentsBecomeOneFamily() {
        assertThat(SecuritySemanticNormalizer.pathFamilyOf(Map.of(), "/api/documents/HX-310-DWG-00001"))
                .isEqualTo("/api/documents/{id}");
        assertThat(SecuritySemanticNormalizer.pathFamilyOf(null, "/api/documents/PLM-OPS-NTE-00028"))
                .isEqualTo("/api/documents/{id}");
        assertThat(SecuritySemanticNormalizer.normalizePathFamily("/api/customers/CUS-0045")).isEqualTo("/api/customers/{id}");
        assertThat(SecuritySemanticNormalizer.normalizePathFamily("/api/orders/42")).isEqualTo("/api/orders/{id}");
        assertThat(SecuritySemanticNormalizer.normalizePathFamily("/api/users/3f2b8c1e-9d4a-4b7e-8f00-1a2b3c4d5e6f"))
                .isEqualTo("/api/users/{id}");
        assertThat(SecuritySemanticNormalizer.normalizePathFamily("/api/blobs/9f86d081884c7d659a2feaa0c55ad015"))
                .isEqualTo("/api/blobs/{id}");
        assertThat(SecuritySemanticNormalizer.normalizePathFamily("/api/accounts/user12345")).isEqualTo("/api/accounts/{id}");
    }

    @Test
    void kindsOfResourcesAndVersionsStay() {
        assertThat(SecuritySemanticNormalizer.normalizePathFamily("/api/v2/reports")).isEqualTo("/api/v2/reports");
        assertThat(SecuritySemanticNormalizer.normalizePathFamily("/api/v2.1/oauth2")).isEqualTo("/api/v2.1/oauth2");
        assertThat(SecuritySemanticNormalizer.normalizePathFamily("/api/admin/role-grants")).isEqualTo("/api/admin/role-grants");
        // A key without digits cannot be told from a word; with a template the host names it.
        assertThat(SecuritySemanticNormalizer.normalizePathFamily("/api/projects/PLM-OPS")).isEqualTo("/api/projects/PLM-OPS");
    }

    @Test
    void aRequestPathIsStillCutAfterItsFourthSegment() {
        assertThat(SecuritySemanticNormalizer.normalizePathFamily("/api/projects/GB-500/exports"))
                .isEqualTo("/api/projects/{id}/exports/*");
        assertThat(SecuritySemanticNormalizer.normalizePathFamily("/admin/api/security-test/sensitive/baseline-3"))
                .isEqualTo("/admin/api/security-test/sensitive/*");
    }

    @Test
    void normalizingAPathFamilyAgainGivesTheSameFamily() {
        for (String path : new String[] {"/api/projects/{projectKey}/exports/async", "/api/projects/GB-500/exports",
                "/api/documents/HX-310-DWG-00001", "/admin/api/security-test/sensitive/baseline-3", "/api/v2/reports"}) {
            String family = SecuritySemanticNormalizer.normalizePathFamily(path);
            assertThat(SecuritySemanticNormalizer.normalizePathFamily(family)).as(path).isEqualTo(family);
        }
    }
}
