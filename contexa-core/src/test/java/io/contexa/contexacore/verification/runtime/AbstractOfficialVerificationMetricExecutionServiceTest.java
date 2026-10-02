package io.contexa.contexacore.verification.runtime;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class AbstractOfficialVerificationMetricExecutionServiceTest {

    private static final String PROBE_PATH =
            "/contexa/admin/api/enterprise/verification/runtime/probe/normal/resource-001";

    @Test
    @DisplayName("every server issued probe should carry a valid runtime override capability")
    void invokeProbeRequestShouldAttachRuntimeOverrideCapability() {
        AtomicReference<Map<String, String>> sentHeaders = new AtomicReference<>();
        ProbeOnlyExecutionService service = new ProbeOnlyExecutionService((baseUrl, requestPath, headers, timeout) -> {
            sentHeaders.set(headers);
            return Map.of();
        });

        service.probeForwarding(OfficialVerificationExecutionRequest.empty(), "X-Request-ID");

        Map<String, String> headers = sentHeaders.get();
        assertThat(headers).containsKey(OfficialVerificationProbeHeaders.RUNTIME_OVERRIDE_CAPABILITY);
        assertThat(OfficialVerificationProbeHeaders.isAuthorizedRuntimeOverride(
                headers.get(OfficialVerificationProbeHeaders.RUNTIME_OVERRIDE_CAPABILITY))).isTrue();
        assertThat(headers).doesNotContainKey(OfficialVerificationProbeHeaders.FAULT_CAPABILITY);
    }

    @Test
    @DisplayName("forwarded client capability header should be replaced by the server issued value")
    void invokeProbeRequestShouldReplaceForwardedClientCapability() {
        AtomicReference<Map<String, String>> sentHeaders = new AtomicReference<>();
        ProbeOnlyExecutionService service = new ProbeOnlyExecutionService((baseUrl, requestPath, headers, timeout) -> {
            sentHeaders.set(headers);
            return Map.of();
        });
        OfficialVerificationExecutionRequest request = new OfficialVerificationExecutionRequest(
                Map.of(OfficialVerificationProbeHeaders.RUNTIME_OVERRIDE_CAPABILITY, "client-forged-capability"),
                Map.of(),
                "http",
                "localhost",
                8080,
                "operator",
                null);

        service.probeForwarding(request, OfficialVerificationProbeHeaders.RUNTIME_OVERRIDE_CAPABILITY);

        String capability = sentHeaders.get().get(OfficialVerificationProbeHeaders.RUNTIME_OVERRIDE_CAPABILITY);
        assertThat(capability).isNotEqualTo("client-forged-capability");
        assertThat(OfficialVerificationProbeHeaders.isAuthorizedRuntimeOverride(capability)).isTrue();
        assertThat(OfficialVerificationProbeHeaders.isAuthorizedRuntimeOverride("client-forged-capability")).isFalse();
    }

    private static final class ProbeOnlyExecutionService extends AbstractOfficialVerificationMetricExecutionService<String> {

        private ProbeOnlyExecutionService(OfficialVerificationProbeClient probeClient) {
            super("TEST", null, null, null, probeClient, null, run -> run, run -> run);
        }

        private Map<String, Object> probeForwarding(OfficialVerificationExecutionRequest request, String forwardedHeader) {
            return invokeProbeRequest(request, PROBE_PATH, headers -> copyHeader(request, headers, forwardedHeader));
        }
    }
}
