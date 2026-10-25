package io.contexa.showcase.workload.contexa.observation;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

/**
 * docs/agent A6-R10 (development only, {@code showcase.dev.model-outage}): the judging model is unavailable for the runs
 * an operator names. The model provider answers a request whose prompt names such a run with the quota error a real
 * provider gives when its quota is used up, without the request leaving the host. It sits at the HTTP boundary of the
 * model provider, inside the capture of {@link ProviderHttpCapture}, so the engine meets exactly what an outage looks
 * like to it: a model call that fails. Calls that name no marked run, and every other HTTP call, pass untouched, so the
 * outage of one run never reaches another run's decisions.
 *
 * <p>A client error is answered (not a server error) because the provider client retries server errors with a growing
 * delay, which would make one request wait for minutes; a quota error fails at once, as a used-up quota does.</p>
 */
public class ModelOutage implements ClientHttpRequestInterceptor {

    /** The run marker: the 12 hexadecimal digits the run's principal and agent names carry. */
    static final Pattern RUN = Pattern.compile("[0-9a-f]{12}");
    static final String BODY = "{\"error\":{\"message\":\"You exceeded your current quota (injected by "
            + "showcase.dev.model-outage)\",\"type\":\"insufficient_quota\",\"code\":\"insufficient_quota\"}}";

    private final Set<String> runs = ConcurrentHashMap.newKeySet();
    private final AtomicLong refused = new AtomicLong();

    /** From now on model calls whose prompt names the run fail. */
    public void begin(String run) {
        runs.add(requireRun(run));
    }

    public void end(String run) {
        runs.remove(requireRun(run));
    }

    /** The runs in outage, and how many model calls the outage has refused. */
    public Set<String> runs() {
        return Set.copyOf(runs);
    }

    public long refusedCalls() {
        return refused.get();
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        if (runs.isEmpty() || request.getMethod() != HttpMethod.POST || !isModelCall(request.getURI().getPath())) {
            return execution.execute(request, body);
        }
        String prompt = new String(body, StandardCharsets.UTF_8);
        for (String run : runs) {
            if (prompt.contains(run)) {
                refused.incrementAndGet();
                return new QuotaError();
            }
        }
        return execution.execute(request, body);
    }

    private static boolean isModelCall(String path) {
        return path.endsWith(ProviderHttpCapture.CHAT_PATH) || path.endsWith(ProviderHttpCapture.MESSAGES_PATH);
    }

    private static String requireRun(String run) {
        if (run == null || !RUN.matcher(run).matches()) {
            throw new IllegalArgumentException("A run marker is 12 lowercase hexadecimal digits");
        }
        return run;
    }

    /** The provider's answer of a used-up quota: HTTP 429 with the error body. */
    private static final class QuotaError implements ClientHttpResponse {

        private final byte[] body = BODY.getBytes(StandardCharsets.UTF_8);

        @Override
        public HttpStatusCode getStatusCode() {
            return HttpStatus.TOO_MANY_REQUESTS;
        }

        @Override
        public String getStatusText() {
            return HttpStatus.TOO_MANY_REQUESTS.getReasonPhrase();
        }

        @Override
        public HttpHeaders getHeaders() {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            return headers;
        }

        @Override
        public InputStream getBody() {
            return new ByteArrayInputStream(body);
        }

        @Override
        public void close() {
            // Nothing is held.
        }
    }
}
