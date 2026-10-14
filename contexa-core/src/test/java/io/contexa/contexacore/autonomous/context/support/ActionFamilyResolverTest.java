package io.contexa.contexacore.autonomous.context.support;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The action family of a request comes from one order of sources (W2-1): a declared value, the protected method's
 * name, the fixed words of the URL template, the HTTP method. The result says which source decided it and whether it
 * was declared or inferred.
 */
class ActionFamilyResolverTest {

    private static final String EXPORT_METHOD =
            "io.contexa.showcase.workload.contexa.business.ContexaBusinessOperations.exportDocuments";

    @Test
    void aDeclaredValueComesFirstAndIsAHostFact() {
        ActionFamilyResolver.Resolution resolution = ActionFamilyResolver.resolve(Map.of(
                "actionFamily", "EXPORT", "protectableMethod", "x.Y.readDocument", "httpMethod", "GET"));

        assertThat(resolution.family()).isEqualTo(ActionFamily.EXPORT);
        assertThat(resolution.source()).isEqualTo("host:actionFamily");
        assertThat(resolution.inferred()).isFalse();
    }

    @Test
    void theProtectedMethodsDeclaredActionComesAfterTheRequestsAndBeforeTheInference() {
        ActionFamilyResolver.Resolution declared = ActionFamilyResolver.resolve(Map.of(
                "protectableActionFamily", "EXPORT", "protectableMethod", "x.Y.readDocument", "httpMethod", "GET"));
        ActionFamilyResolver.Resolution requestFirst = ActionFamilyResolver.resolve(Map.of(
                "actionFamily", "READ", "protectableActionFamily", "EXPORT"));

        // W2-11: the descriptor of the protected method is a host declaration, below what the request declares.
        assertThat(declared.family()).isEqualTo(ActionFamily.EXPORT);
        assertThat(declared.source()).isEqualTo("host:protectableActionFamily");
        assertThat(requestFirst.family()).isEqualTo(ActionFamily.READ);
    }

    @Test
    void aDeclaredUnknownStatesNothingAndTheOtherSourcesDecide() {
        ActionFamilyResolver.Resolution resolution = ActionFamilyResolver.resolve(Map.of(
                "actionFamily", "UNKNOWN", "protectableMethod", EXPORT_METHOD, "httpMethod", "POST"));

        assertThat(resolution.family()).isEqualTo(ActionFamily.EXPORT);
        assertThat(resolution.source()).isEqualTo("inferred:protectableMethod");
    }

    @Test
    void theProtectedMethodNameDecidesBeforeTheHttpMethod() {
        ActionFamilyResolver.Resolution export = ActionFamilyResolver.resolve(Map.of(
                "protectableMethod", EXPORT_METHOD, "httpMethod", "POST"));
        ActionFamilyResolver.Resolution download = ActionFamilyResolver.resolve(Map.of(
                "protectableMethod", "x.Y#downloadDocument", "httpMethod", "GET"));

        assertThat(export.family()).isEqualTo(ActionFamily.EXPORT);
        assertThat(export.sourceKey()).isEqualTo("protectableMethod");
        assertThat(export.inferred()).isTrue();
        assertThat(download.family()).isEqualTo(ActionFamily.READ);
    }

    @Test
    void theTemplateIsReadWithoutItsVariableSegments() {
        ActionFamilyResolver.Resolution exports = ActionFamilyResolver.resolve(Map.of(
                "protectableResourceUrl", "/api/projects/{projectKey}/exports", "httpMethod", "POST"));
        ActionFamilyResolver.Resolution variableOnly = ActionFamilyResolver.resolve(Map.of(
                "protectableResourceUrl", "/api/items/{exportId}", "httpMethod", "GET"));

        assertThat(exports.family()).isEqualTo(ActionFamily.EXPORT);
        assertThat(exports.source()).isEqualTo("inferred:protectableResourceUrl");
        assertThat(variableOnly.family()).isEqualTo(ActionFamily.READ);
        assertThat(variableOnly.source()).isEqualTo("inferred:httpMethod");
    }

    @Test
    void theHttpMethodIsTheLastSourceAndNothingIsUnknown() {
        ActionFamilyResolver.Resolution patch = ActionFamilyResolver.resolve(Map.of("httpMethod", "PATCH"));
        ActionFamilyResolver.Resolution nothing = ActionFamilyResolver.resolve(Map.of("requestPath", "/api/x"));

        assertThat(patch.family()).isEqualTo(ActionFamily.WRITE);
        assertThat(patch.source()).isEqualTo("inferred:httpMethod");
        assertThat(nothing.family()).isEqualTo(ActionFamily.UNKNOWN);
        assertThat(nothing.source()).isNull();
        assertThat(ActionFamilyResolver.resolve(null).family()).isEqualTo(ActionFamily.UNKNOWN);
    }
}
