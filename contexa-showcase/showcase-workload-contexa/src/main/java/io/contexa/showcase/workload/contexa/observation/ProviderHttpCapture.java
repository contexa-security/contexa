package io.contexa.showcase.workload.contexa.observation;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Captures the chat completion request and response exactly as they cross the HTTP boundary to the model provider
 * (docs/showcase/데모-재설계.md R-23, after the OSS lab's ProviderObservationInterceptor): the request options that
 * were really sent and the provider's response body with its finish reason and reasoning tokens. Only calls opened by
 * {@link LlmUsageMeter} for a decision are captured; every other HTTP call passes untouched. The response body is read
 * once into memory (bounded) and handed on unchanged.
 */
public class ProviderHttpCapture implements ClientHttpRequestInterceptor {

    static final String CHAT_PATH = "/chat/completions";

    private final ModelExchanges exchanges;

    public ProviderHttpCapture(ModelExchanges exchanges) {
        this.exchanges = exchanges;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        ModelExchanges.Pending pending = exchanges.current();
        if (pending == null || request.getMethod() != HttpMethod.POST
                || !request.getURI().getPath().endsWith(CHAT_PATH)) {
            return execution.execute(request, body);
        }
        pending.requestOptions = exchanges.requestOptions(body);
        ClientHttpResponse response = execution.execute(request, body);
        byte[] responseBody = read(response.getBody());
        pending.httpStatus = response.getStatusCode().value();
        pending.providerResponse = responseBody.length > ModelExchanges.MAX_PROVIDER_BODY
                ? null : new String(responseBody, StandardCharsets.UTF_8);
        return new BufferedResponse(response, responseBody);
    }

    private static byte[] read(InputStream body) throws IOException {
        if (body == null) {
            return new byte[0];
        }
        try (InputStream in = body; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            in.transferTo(out);
            return out.toByteArray();
        }
    }

    /** The provider's response with its body already read, so the chat client reads the same bytes. */
    private static final class BufferedResponse implements ClientHttpResponse {

        private final ClientHttpResponse delegate;
        private final byte[] body;

        BufferedResponse(ClientHttpResponse delegate, byte[] body) {
            this.delegate = delegate;
            this.body = body;
        }

        @Override
        public HttpStatusCode getStatusCode() throws IOException {
            return delegate.getStatusCode();
        }

        @Override
        public String getStatusText() throws IOException {
            return delegate.getStatusText();
        }

        @Override
        public HttpHeaders getHeaders() {
            return delegate.getHeaders();
        }

        @Override
        public InputStream getBody() {
            return new ByteArrayInputStream(body);
        }

        @Override
        public void close() {
            delegate.close();
        }
    }
}
