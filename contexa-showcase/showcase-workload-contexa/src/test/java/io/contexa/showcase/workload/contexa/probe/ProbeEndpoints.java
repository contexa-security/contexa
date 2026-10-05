package io.contexa.showcase.workload.contexa.probe;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.event.EventListener;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Probe-only protected endpoints and the engine event recorder. The business API arrives in P1; the probes need
 * only a protected method, a streaming response and a view of the events the engine produces.
 */
@TestConfiguration(proxyBeanMethods = false)
class ProbeEndpoints {

    @Bean
    ProbeDocumentService probeDocumentService() {
        return new ProbeDocumentService();
    }

    @Bean
    ProtectableEventRecorder protectableEventRecorder() {
        return new ProtectableEventRecorder();
    }

    static class ProbeDocumentService {

        @Protectable
        public String read(String documentId) {
            return "document-" + documentId;
        }
    }

    /** Registered by the application's component scan, which also covers this test package. */
    @RestController
    static class ProbeController {

        private final ProbeDocumentService documents;

        ProbeController(ProbeDocumentService documents) {
            this.documents = documents;
        }

        @GetMapping("/probe/documents/{id}")
        Map<String, String> document(@PathVariable("id") String id) {
            return Map.of("document", documents.read(id));
        }

        /** Asynchronous export stream: one row every 100 ms. */
        @GetMapping(value = "/probe/stream", produces = MediaType.APPLICATION_NDJSON_VALUE)
        ResponseEntity<StreamingResponseBody> stream(@RequestParam(name = "rows", defaultValue = "50") int rows) {
            StreamingResponseBody body = out -> {
                for (int row = 1; row <= rows; row++) {
                    out.write(("{\"row\":" + row + "}\n").getBytes(StandardCharsets.UTF_8));
                    out.flush();
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            };
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_NDJSON).body(body);
        }
    }

    /** Every event published by a protected call, whether or not the engine hands it to analysis. */
    static class ProtectableEventRecorder {

        private final ConcurrentLinkedQueue<ZeroTrustSpringEvent> events = new ConcurrentLinkedQueue<>();

        @EventListener
        void on(ZeroTrustSpringEvent event) {
            events.add(event);
        }

        Optional<ZeroTrustSpringEvent> byRequestId(String requestId) {
            return events.stream()
                    .filter(event -> Objects.equals(requestId, event.getPayload().get("requestId")))
                    .findFirst();
        }

        List<ZeroTrustSpringEvent> byUser(String userId) {
            return events.stream().filter(event -> userId.equals(event.getUserId())).toList();
        }
    }
}
