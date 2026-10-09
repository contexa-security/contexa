package io.contexa.showcase.business.client;

import io.contexa.showcase.business.internal.InternalContext;
import io.contexa.showcase.business.internal.InternalContextFilter;
import io.contexa.showcase.business.internal.InternalContextHeaders;
import io.contexa.showcase.business.internal.InternalContextSigner;

import java.io.IOException;
import java.io.InputStream;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * HTTP client of one run against one control: its own cookie store (each control keeps its own session) and the
 * signed internal context of the run on every request (docs/showcase/연결계약.md). The portal orchestrator and the
 * workload tests use it.
 */
public final class WorkloadClient {

    /**
     * The synthetic identity of a run as the workloads see it; constant for the whole run, except the address of a
     * template learning that replays work done from another network ({@link #withClientIp}).
     */
    public record RunIdentity(String runId, String organization, String tenant, String clientIp, String device) {
    }

    /**
     * @param sentAt  wall-clock time the request left
     * @param elapsed until the whole body was read
     */
    public record Response(int status, Map<String, List<String>> headers, byte[] body, Instant sentAt,
                           Duration elapsed) {

        public String text() {
            return new String(body, StandardCharsets.UTF_8);
        }

        public Optional<String> header(String name) {
            return headers.entrySet().stream()
                    .filter(entry -> entry.getKey().equalsIgnoreCase(name))
                    .flatMap(entry -> entry.getValue().stream())
                    .findFirst();
        }
    }

    private final URI base;
    private final InternalContextSigner signer;
    private final RunIdentity run;
    private final Clock clock;
    private final CookieManager cookies;
    private final HttpClient http;
    private final Duration timeout;

    public WorkloadClient(URI base, InternalContextSigner signer, RunIdentity run, Duration timeout) {
        this.base = base;
        this.signer = signer;
        this.run = run;
        this.clock = Clock.systemUTC();
        this.timeout = timeout;
        this.cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        this.http = HttpClient.newBuilder()
                .cookieHandler(cookies)
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    private WorkloadClient(WorkloadClient source, RunIdentity run) {
        this.base = source.base;
        this.signer = source.signer;
        this.run = run;
        this.clock = source.clock;
        this.timeout = source.timeout;
        this.cookies = source.cookies;
        this.http = source.http;
    }

    public RunIdentity run() {
        return run;
    }

    /**
     * The same session (the cookie store is shared) sending from another address, as an employee who signed in at
     * the office and later works from a registered trip network.
     */
    public WorkloadClient withClientIp(String clientIp) {
        if (clientIp == null || clientIp.isBlank() || clientIp.equals(run.clientIp())) {
            return this;
        }
        return new WorkloadClient(this, new RunIdentity(run.runId(), run.organization(), run.tenant(), clientIp,
                run.device()));
    }

    public Response get(String pathAndQuery, String requestId, Instant observedAt) throws IOException {
        return send(signed("GET", pathAndQuery, requestId, observedAt).GET().header("Accept", "application/json"));
    }

    public Response delete(String pathAndQuery, String requestId) throws IOException {
        return send(signed("DELETE", pathAndQuery, requestId, null).DELETE().header("Accept", "application/json"));
    }

    public Response postJson(String pathAndQuery, String requestId, Instant observedAt, String json)
            throws IOException {
        return send(signed("POST", pathAndQuery, requestId, observedAt)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json == null ? "" : json)));
    }

    public Response postForm(String pathAndQuery, String requestId, Instant observedAt, Map<String, String> form)
            throws IOException {
        String body = form.entrySet().stream()
                .map(entry -> encode(entry.getKey()) + "=" + encode(entry.getValue()))
                .collect(Collectors.joining("&"));
        return send(signed("POST", pathAndQuery, requestId, observedAt)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)));
    }

    /** Opens a streaming response; the caller reads and closes the body. */
    public HttpResponse<InputStream> openStream(String pathAndQuery, String requestId, Instant observedAt)
            throws IOException {
        try {
            return http.send(signed("GET", pathAndQuery, requestId, observedAt).GET()
                    .header("Accept", "application/x-ndjson").build(), HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while opening " + pathAndQuery, e);
        }
    }

    public Optional<String> cookie(String name) {
        return cookies.getCookieStore().getCookies().stream()
                .filter(cookie -> cookie.getName().equals(name))
                .map(HttpCookie::getValue)
                .findFirst();
    }

    private HttpRequest.Builder signed(String method, String pathAndQuery, String requestId, Instant observedAt) {
        URI uri = base.resolve(pathAndQuery);
        InternalContext context = new InternalContext(run.runId(), requestId, observedAt, run.clientIp(),
                run.device(), run.organization(), run.tenant());
        long timestamp = clock.instant().getEpochSecond();
        String path = InternalContextFilter.signedPath(uri.getRawPath(), uri.getRawQuery());
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .timeout(timeout)
                .header(InternalContextHeaders.RUN, run.runId())
                .header(InternalContextHeaders.TIMESTAMP, Long.toString(timestamp))
                .header(InternalContextHeaders.SIGNATURE, signer.sign(method, path, timestamp, context));
        header(builder, InternalContextHeaders.REQUEST_ID, requestId);
        header(builder, InternalContextHeaders.OBSERVED_AT, observedAt == null ? null : observedAt.toString());
        header(builder, InternalContextHeaders.CLIENT_IP, run.clientIp());
        header(builder, InternalContextHeaders.DEVICE, run.device());
        header(builder, InternalContextHeaders.ORGANIZATION, run.organization());
        header(builder, InternalContextHeaders.TENANT, run.tenant());
        if (run.device() != null) {
            builder.header("User-Agent", run.device());
        }
        return builder;
    }

    private Response send(HttpRequest.Builder builder) throws IOException {
        Instant sentAt = clock.instant();
        long started = System.nanoTime();
        try {
            HttpResponse<byte[]> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
            return new Response(response.statusCode(), response.headers().map(), response.body(), sentAt,
                    Duration.ofNanos(System.nanoTime() - started));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while calling " + builder.build().uri(), e);
        }
    }

    private static void header(HttpRequest.Builder builder, String name, String value) {
        if (value != null && !value.isBlank()) {
            builder.header(name, value);
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
    }
}
