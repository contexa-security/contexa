package io.contexa.showcase.workload.contexa.model;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Whether an Anthropic key is accepted and a model is available to it, read from the models listing of the API: no
 * model is called and no tokens are spent. Control D asks it before it starts, so a Layer 2 that cannot answer stops the
 * start with the reason instead of turning every escalated decision into a technical fallback.
 */
public final class AnthropicAvailability {

    /** What the API said: ACCEPTED, REFUSED_KEY (401, 403), NO_MODEL (404) or UNKNOWN (anything else, or no answer). */
    public enum Outcome {
        ACCEPTED,
        REFUSED_KEY,
        NO_MODEL,
        UNKNOWN
    }

    public record Result(Outcome outcome, int status, String detail) {
    }

    private static final String VERSION = "2023-06-01";
    private static final Duration TIMEOUT = Duration.ofSeconds(15);

    private AnthropicAvailability() {
    }

    public static Result check(String baseUrl, String apiKey, String model) {
        String base = baseUrl == null || baseUrl.isBlank() ? "https://api.anthropic.com" : baseUrl.trim();
        String path = (base.endsWith("/") ? base.substring(0, base.length() - 1) : base) + "/v1/models/" + model;
        HttpRequest request = HttpRequest.newBuilder(URI.create(path)).timeout(TIMEOUT)
                .header("x-api-key", apiKey).header("anthropic-version", VERSION).GET().build();
        try {
            HttpResponse<String> response = HttpClient.newBuilder().connectTimeout(TIMEOUT).build()
                    .send(request, HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();
            if (status == 200) {
                return new Result(Outcome.ACCEPTED, status, "");
            }
            if (status == 401 || status == 403) {
                return new Result(Outcome.REFUSED_KEY, status, "");
            }
            if (status == 404) {
                return new Result(Outcome.NO_MODEL, status, "");
            }
            return new Result(Outcome.UNKNOWN, status, "HTTP " + status);
        } catch (IOException e) {
            return new Result(Outcome.UNKNOWN, 0, e.getClass().getSimpleName() + ": " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Result(Outcome.UNKNOWN, 0, "interrupted");
        }
    }
}
