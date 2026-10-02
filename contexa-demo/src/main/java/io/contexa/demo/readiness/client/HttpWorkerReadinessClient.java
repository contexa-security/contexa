package io.contexa.demo.readiness.client;

import io.contexa.demo.readiness.dto.ReadinessReport;
import io.contexa.demo.readiness.dto.WorkerReadiness;
import io.contexa.demo.shared.document.DocumentCodec;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CompletableFuture;

@Component
public class HttpWorkerReadinessClient implements WorkerReadinessClient {

    private final DocumentCodec documents;
    private final HttpClient client =
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).followRedirects(HttpClient.Redirect.NEVER)
                    .build();

    public HttpWorkerReadinessClient(DocumentCodec documents) {
        this.documents = documents;
    }

    public CompletableFuture<WorkerReadiness> inspect(String role, URI endpoint) {
        Instant now = Instant.now();
        if (endpoint == null || !List.of("http", "https").contains(endpoint.getScheme()) ||
                endpoint.getHost() == null || endpoint.getUserInfo() != null) {
            return CompletableFuture.completedFuture(
                    new WorkerReadiness(role, now, "INVALID_CONFIGURATION", null, null));
        }
        var request =
                HttpRequest.newBuilder(endpoint.resolve("/api/lab/readiness/local")).timeout(Duration.ofSeconds(3))
                        .header("Accept", "application/json").GET().build();
        return client.sendAsync(request, HttpResponse.BodyHandlers.ofString()).handle((response, failure) -> {
            if (failure != null) {
                return new WorkerReadiness(role, now, "UNAVAILABLE", null, null);
            }
            if (response.statusCode() != 200) {
                return new WorkerReadiness(role, now, "UNAVAILABLE", response.statusCode(), null);
            }
            try {
                var report = documents.read(response.body(), ReadinessReport.class);
                if (!role.equals(report.role()) || report.observedAt() == null || report.checks() == null ||
                        report.workers() == null || !report.workers().isEmpty()) {
                    return new WorkerReadiness(role, now, "INVALID_RESPONSE", response.statusCode(), null);
                }
                return new WorkerReadiness(role, now, "REACHABLE", 200, report);
            } catch (RuntimeException invalid) {
                return new WorkerReadiness(role, now, "INVALID_RESPONSE", 200, null);
            }
        });
    }
}
