package io.contexa.showcase.workload.contexa.probe;

import io.contexa.showcase.business.internal.InternalContext;
import io.contexa.showcase.business.internal.InternalContextFilter;
import io.contexa.showcase.business.internal.InternalContextHeaders;
import io.contexa.showcase.business.internal.InternalContextSigner;

import java.io.IOException;
import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Plays the portal orchestrator for one run: its own cookie store, and every request signed with the run's
 * internal context. Each request receives a new decision id unless the caller passes one.
 */
final class ProbeClient {

    private final URI base;
    private final InternalContextSigner signer;
    private final RunIdentity run;
    private final CookieManager cookies = new CookieManager();
    private final HttpClient http;

    ProbeClient(URI base, InternalContextSigner signer, RunIdentity run) {
        this.base = base;
        this.signer = signer;
        this.run = run;
        this.http = HttpClient.newBuilder()
                .cookieHandler(cookies)
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    /** Current value of a cookie held for this run, or null. */
    String cookie(String name) {
        return cookies.getCookieStore().getCookies().stream()
                .filter(cookie -> cookie.getName().equals(name)).map(HttpCookie::getValue)
                .findFirst().orElse(null);
    }

    RunIdentity run() {
        return run;
    }

    Call call(String method, String path) {
        return new Call(method, path);
    }

    HttpResponse<String> postJson(String path, String json) throws IOException, InterruptedException {
        return call("POST", path).json(json).send();
    }

    HttpResponse<String> postForm(String path, Map<String, String> form) throws IOException, InterruptedException {
        return call("POST", path).form(form).send();
    }

    HttpResponse<String> getJson(String path) throws IOException, InterruptedException {
        return call("GET", path).send();
    }

    static String newRequestId() {
        return UUID.randomUUID().toString();
    }

    final class Call {

        private final String method;
        private final String path;
        private String requestId = newRequestId();
        private Instant observedAt;
        private String contentType;
        private String body = "";
        private String accept = "application/json";
        private final Map<String, String> extraHeaders = new LinkedHashMap<>();
        private boolean signed = true;
        private InternalContextSigner signingOverride;

        private Call(String method, String path) {
            this.method = method;
            this.path = path;
        }

        Call requestId(String value) {
            this.requestId = value;
            return this;
        }

        Call observedAt(Instant value) {
            this.observedAt = value;
            return this;
        }

        Call accept(String value) {
            this.accept = value;
            return this;
        }

        Call header(String name, String value) {
            extraHeaders.put(name, value);
            return this;
        }

        Call unsigned() {
            this.signed = false;
            return this;
        }

        Call signedWith(InternalContextSigner otherSigner) {
            this.signingOverride = otherSigner;
            return this;
        }

        Call json(String json) {
            this.contentType = "application/json";
            this.body = json;
            return this;
        }

        Call form(Map<String, String> form) {
            this.contentType = "application/x-www-form-urlencoded";
            this.body = form.entrySet().stream()
                    .map(entry -> encode(entry.getKey()) + "=" + encode(entry.getValue()))
                    .collect(Collectors.joining("&"));
            return this;
        }

        String requestId() {
            return requestId;
        }

        HttpResponse<String> send() throws IOException, InterruptedException {
            return http.send(build(), HttpResponse.BodyHandlers.ofString());
        }

        HttpResponse<Stream<String>> sendStreaming() throws IOException, InterruptedException {
            return http.send(build(), HttpResponse.BodyHandlers.ofLines());
        }

        private HttpRequest build() {
            HttpRequest.Builder builder = HttpRequest.newBuilder(base.resolve(path))
                    .timeout(Duration.ofSeconds(30))
                    .method(method, body.isEmpty() && "GET".equals(method)
                            ? HttpRequest.BodyPublishers.noBody()
                            : HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                    .header("Accept", accept);
            if (contentType != null) {
                builder.header("Content-Type", contentType);
            }
            if (signed) {
                InternalContext context = new InternalContext(run.runId(), requestId, observedAt,
                        run.clientIp(), run.device(), run.organization(), run.tenant());
                long timestamp = Instant.now().getEpochSecond();
                URI target = base.resolve(path);
                String signedPath = InternalContextFilter.signedPath(target.getRawPath(), target.getRawQuery());
                InternalContextSigner usedSigner = signingOverride != null ? signingOverride : signer;
                builder.header(InternalContextHeaders.RUN, run.runId())
                        .header(InternalContextHeaders.REQUEST_ID, requestId)
                        .header(InternalContextHeaders.CLIENT_IP, run.clientIp())
                        .header(InternalContextHeaders.DEVICE, run.device())
                        .header(InternalContextHeaders.ORGANIZATION, run.organization())
                        .header(InternalContextHeaders.TENANT, run.tenant())
                        .header(InternalContextHeaders.TIMESTAMP, Long.toString(timestamp))
                        .header(InternalContextHeaders.SIGNATURE,
                                usedSigner.sign(method, signedPath, timestamp, context));
                if (observedAt != null) {
                    builder.header(InternalContextHeaders.OBSERVED_AT, observedAt.toString());
                }
            }
            extraHeaders.forEach(builder::header);
            return builder.build();
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /** Synthetic identity of one run: a fresh principal with its own scope, address and device. */
    record RunIdentity(String runId, String username, String password, String email, String organization,
                       String tenant, String clientIp, String device) {
    }
}
