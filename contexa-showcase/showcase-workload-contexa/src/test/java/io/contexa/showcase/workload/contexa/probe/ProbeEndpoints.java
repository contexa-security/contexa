package io.contexa.showcase.workload.contexa.probe;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import jakarta.servlet.http.HttpServletResponse;
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

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

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

        /** Asynchronous export stream: one row every {@code everyMs} (100 ms unless given). */
        @GetMapping(value = "/probe/stream", produces = MediaType.APPLICATION_NDJSON_VALUE)
        ResponseEntity<StreamingResponseBody> stream(@RequestParam(name = "rows", defaultValue = "50") int rows,
                                                     @RequestParam(name = "everyMs", defaultValue = "100") long everyMs) {
            StreamingResponseBody body = out -> {
                for (int row = 1; row <= rows; row++) {
                    out.write(row(row));
                    out.flush();
                    if (!pause(everyMs)) {
                        return;
                    }
                }
            };
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_NDJSON).body(body);
        }

        /** Synchronous export stream written on the request thread: one row every {@code everyMs}. */
        @GetMapping(value = "/probe/stream-sync", produces = MediaType.APPLICATION_NDJSON_VALUE)
        void streamSync(@RequestParam(name = "rows", defaultValue = "50") int rows,
                        @RequestParam(name = "everyMs", defaultValue = "100") long everyMs,
                        HttpServletResponse response) throws IOException {
            response.setContentType(MediaType.APPLICATION_NDJSON_VALUE);
            OutputStream out = response.getOutputStream();
            for (int row = 1; row <= rows; row++) {
                out.write(row(row));
                out.flush();
                if (!pause(everyMs)) {
                    return;
                }
            }
        }

        /** Two rows into the buffer without a flush, held until the probe releases it, then a third row. */
        @GetMapping(value = "/probe/stream-held", produces = MediaType.APPLICATION_NDJSON_VALUE)
        ResponseEntity<StreamingResponseBody> streamHeld(@RequestParam("id") String id) {
            Hold hold = hold(id);
            StreamingResponseBody body = out -> {
                out.write(row(1));
                out.write(row(2));
                hold.holding.countDown();
                try {
                    if (!hold.release.await(20, TimeUnit.SECONDS)) {
                        return;
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                out.write(row(3));
                out.flush();
            };
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_NDJSON).body(body);
        }

        private static final Map<String, Hold> HOLDS = new ConcurrentHashMap<>();

        static Hold hold(String id) {
            return HOLDS.computeIfAbsent(id, key -> new Hold());
        }

        static final class Hold {

            final CountDownLatch holding = new CountDownLatch(1);
            final CountDownLatch release = new CountDownLatch(1);
        }

        private static byte[] row(int row) {
            return ("{\"row\":" + row + "}\n").getBytes(StandardCharsets.UTF_8);
        }

        private static boolean pause(long millis) {
            try {
                Thread.sleep(millis);
                return true;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
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
