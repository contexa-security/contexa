package io.contexa.contexacore.autonomous.context.support;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A past record relates to the request through the path template and the target the path names (W2-8, A-8): the same
 * protected method on another project is the same action on a different resource, never the same resource.
 */
class PastRecordRelevanceTest {

    private static final String EXPORT_METHOD =
            "io.contexa.showcase.workload.contexa.business.ContexaBusinessOperations#exportDocuments";
    private static final String EXPORTS = "/api/projects/{projectKey}/exports";

    @Test
    void aRecordOfTheSameProjectExportIsTheSameResource() {
        PastRecordRelevance.Subject request = exportRequest("GB-500");
        PastRecordRelevance.Subject record = exportRecord("GB-500");

        assertThat(request.target()).isEqualTo("projectKey=GB-500");
        assertThat(PastRecordRelevance.relation(request, record)).isEqualTo(PastRecordRelevance.Relation.SAME_TARGET);
        assertThat(PastRecordRelevance.sameTarget(request, record)).isEqualTo("yes");
        assertThat(PastRecordRelevance.relevance(request, List.of(record))).isEqualTo("SAME_RESOURCE");
    }

    @Test
    void anExportOfAnotherProjectIsTheSameActionOnADifferentResourceThoughTheMethodIsTheSame() {
        PastRecordRelevance.Subject request = exportRequest("GB-500");
        List<PastRecordRelevance.Subject> records = List.of(exportRecord("PLM-OPS"), exportRecord("PLM-OPS"));

        assertThat(PastRecordRelevance.relation(request, records.get(0)))
                .isEqualTo(PastRecordRelevance.Relation.SAME_ACTION_OTHER_TARGET);
        assertThat(PastRecordRelevance.sameTarget(request, records.get(0))).isEqualTo("no");
        assertThat(PastRecordRelevance.relevance(request, records)).isEqualTo("SAME_ACTION_DIFFERENT_RESOURCE");
    }

    @Test
    void recordsOfTheSameAndOfAnotherTargetTogetherAreMixed() {
        PastRecordRelevance.Subject request = exportRequest("GB-500");

        assertThat(PastRecordRelevance.relevance(request, List.of(exportRecord("GB-500"), exportRecord("PLM-OPS"))))
                .isEqualTo("MIXED_OR_DIFFERENT_RESOURCE");
    }

    @Test
    void anotherActionOnTheSameTargetIsAnotherActionYetTheSameTarget() {
        PastRecordRelevance.Subject request = exportRequest("GB-500");
        PastRecordRelevance.Subject read = PastRecordRelevance.Subject.ofRecord(Map.of(
                "requestPath", "/api/projects/GB-500/exports",
                "pathFamily", EXPORTS,
                "actionFamily", "READ",
                "httpMethod", "GET"), null);

        assertThat(PastRecordRelevance.relation(request, read)).isEqualTo(PastRecordRelevance.Relation.OTHER_ACTION);
        assertThat(PastRecordRelevance.sameTarget(request, read)).isEqualTo("yes");
        assertThat(PastRecordRelevance.relevance(request, List.of(read))).isEqualTo("MIXED_OR_DIFFERENT_RESOURCE");
    }

    @Test
    void anotherPathTemplateIsAnotherAction() {
        PastRecordRelevance.Subject request = exportRequest("GB-500");
        PastRecordRelevance.Subject document = PastRecordRelevance.Subject.ofRecord(Map.of(
                "requestPath", "/api/documents/HX-310-DWG-00001/download",
                "pathFamily", "/api/documents/{documentKey}/download",
                "resourceId", EXPORT_METHOD), null);

        assertThat(PastRecordRelevance.relation(request, document)).isEqualTo(PastRecordRelevance.Relation.OTHER_ACTION);
        assertThat(PastRecordRelevance.sameTarget(request, document)).isEqualTo("no");
    }

    @Test
    void theTargetIsTheSetOfTheTemplateValuesAndTheQueryIsNotPartOfIt() {
        PastRecordRelevance.Subject request = PastRecordRelevance.Subject.ofRequest(Map.of(
                "requestPath", "/api/projects/GB-500/documents/D-7?page=2",
                "protectableResourceUrl", "/api/projects/{projectKey}/documents/{documentKey}"), null);
        PastRecordRelevance.Subject record = PastRecordRelevance.Subject.ofRecord(Map.of(
                "requestPath", "/api/projects/GB-500/documents/D-7",
                "pathFamily", "/api/projects/{projectKey}/documents/{documentKey}"), null);
        PastRecordRelevance.Subject projectOnly = PastRecordRelevance.Subject.ofRecord(Map.of(
                "requestPath", "/api/projects/GB-500/exports", "pathFamily", EXPORTS), null);

        PastRecordRelevance.Subject documentFirst = PastRecordRelevance.Subject.ofRecord(Map.of(
                "requestPath", "/api/documents/D-7/projects/GB-500",
                "pathFamily", "/api/documents/{documentKey}/projects/{projectKey}"), null);

        assertThat(request.path()).isEqualTo("/api/projects/GB-500/documents/D-7");
        assertThat(request.target()).isEqualTo("projectKey=GB-500,documentKey=D-7");
        assertThat(PastRecordRelevance.sameTarget(request, record)).isEqualTo("yes");
        assertThat(PastRecordRelevance.sameTarget(request, projectOnly)).isEqualTo("no");
        // The same values named in another order are the same target, though another template is another action.
        assertThat(documentFirst.target()).isEqualTo("documentKey=D-7,projectKey=GB-500");
        assertThat(PastRecordRelevance.sameTarget(request, documentFirst)).isEqualTo("yes");
        assertThat(PastRecordRelevance.relation(request, documentFirst))
                .isEqualTo(PastRecordRelevance.Relation.OTHER_ACTION);
    }

    @Test
    void aPathWithoutATemplateComparesItsIdentifierSegments() {
        PastRecordRelevance.Subject request = PastRecordRelevance.Subject.ofRequest(
                Map.of("requestPath", "/api/customers/C-1001", "httpMethod", "GET"), null);
        PastRecordRelevance.Subject same = PastRecordRelevance.Subject.ofRecord(
                Map.of("requestPath", "/api/customers/C-1001", "httpMethod", "GET"), null);
        PastRecordRelevance.Subject other = PastRecordRelevance.Subject.ofRecord(
                Map.of("requestPath", "/api/customers/C-2002", "httpMethod", "GET"), null);

        assertThat(request.pathFamily()).isEqualTo("/api/customers/{id}");
        assertThat(PastRecordRelevance.relation(request, same)).isEqualTo(PastRecordRelevance.Relation.SAME_TARGET);
        assertThat(PastRecordRelevance.relation(request, other))
                .isEqualTo(PastRecordRelevance.Relation.SAME_ACTION_OTHER_TARGET);
    }

    @Test
    void aCutPathKnowsItsTargetOnlyWhenThePathsAreTheSame() {
        PastRecordRelevance.Subject request = PastRecordRelevance.Subject.ofRequest(
                Map.of("requestPath", "/admin/api/security-test/sensitive/resource-001"), null);
        PastRecordRelevance.Subject same = PastRecordRelevance.Subject.ofRecord(
                Map.of(), "User accessed /admin/api/security-test/sensitive/resource-001 via GET");
        PastRecordRelevance.Subject other = PastRecordRelevance.Subject.ofRecord(
                Map.of("requestPath", "/admin/api/security-test/sensitive/resource-002"), null);

        assertThat(same.path()).isEqualTo("/admin/api/security-test/sensitive/resource-001");
        assertThat(PastRecordRelevance.relation(request, same)).isEqualTo(PastRecordRelevance.Relation.SAME_TARGET);
        assertThat(PastRecordRelevance.relation(request, other)).isEqualTo(PastRecordRelevance.Relation.UNKNOWN);
        assertThat(PastRecordRelevance.sameTarget(request, other)).isEqualTo("unknown");
        assertThat(PastRecordRelevance.relevance(request, List.of(other))).isEqualTo("UNKNOWN");
    }

    @Test
    void aRequestWithoutAPathOrNoRecordsSaysSo() {
        PastRecordRelevance.Subject noPath = PastRecordRelevance.Subject.ofRequest(
                Map.of("resourceId", EXPORT_METHOD), null);

        assertThat(PastRecordRelevance.relevance(noPath, List.of(exportRecord("GB-500")))).isEqualTo("UNKNOWN");
        assertThat(PastRecordRelevance.relevance(exportRequest("GB-500"), List.of())).isEqualTo("NO_DOCUMENTS");
    }

    @Test
    void theRequestPathComesFromTheDescriptionWhenNoPathIsSet() {
        PastRecordRelevance.Subject request = PastRecordRelevance.Subject.ofRequest(
                Map.of("protectableResourceUrl", EXPORTS), "POST /api/projects/GB-500/exports");

        assertThat(request.path()).isEqualTo("/api/projects/GB-500/exports");
        assertThat(request.target()).isEqualTo("projectKey=GB-500");
    }

    private static PastRecordRelevance.Subject exportRequest(String project) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("requestPath", "/api/projects/" + project + "/exports");
        metadata.put("protectableResourceUrl", EXPORTS);
        metadata.put("resourceId", EXPORT_METHOD);
        metadata.put("httpMethod", "POST");
        metadata.put("protectableMethod", EXPORT_METHOD.replace('#', '.'));
        return PastRecordRelevance.Subject.ofRequest(metadata, null);
    }

    private static PastRecordRelevance.Subject exportRecord(String project) {
        return PastRecordRelevance.Subject.ofRecord(Map.of(
                "requestPath", "/api/projects/" + project + "/exports",
                "pathFamily", EXPORTS,
                "resourceId", EXPORT_METHOD,
                "actionFamily", "EXPORT",
                "httpMethod", "POST"), null);
    }
}
