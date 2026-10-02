package io.contexa.demo.observation.provider.http;

import io.contexa.demo.observation.model.call.ModelCallContext;
import io.contexa.demo.observation.model.call.ModelCallReference;
import io.contexa.demo.observation.provider.service.ProviderBodySanitizer;
import io.contexa.demo.observation.provider.service.ProviderHttpSink;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Set;
import java.util.UUID;

@Component
@Profile("contexa")
public class ProviderObservationInterceptor implements ClientHttpRequestInterceptor {

    private static final Logger log = LoggerFactory.getLogger(ProviderObservationInterceptor.class);
    private static final Set<String> PATHS = Set.of("/v1/chat/completions", "/api/chat");
    private final ModelCallContext calls;
    private final ProviderBodySanitizer sanitizer;
    private final ProviderHttpSink sink;

    public ProviderObservationInterceptor(ModelCallContext calls, ProviderBodySanitizer sanitizer,
            ProviderHttpSink sink) {
        this.calls = calls;
        this.sanitizer = sanitizer;
        this.sink = sink;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        ProviderExchangeCapture capture = prepare(request, body);
        if (capture == null) {
            return execution.execute(request, body);
        }
        try {
            return new ObservedProviderResponse(execution.execute(request, body), capture);
        } catch (IOException | RuntimeException failure) {
            capture.failed(failure);
            capture.finish();
            throw failure;
        }
    }

    private ProviderExchangeCapture prepare(HttpRequest request, byte[] body) {
        try {
            ModelCallReference call = calls.current();
            if (call == null || call.source() == null || call.source().requestId() == null
                    || call.source().eventId() == null || call.source().processingGeneration() == null
                    || call.source().pipelineRequestId() == null || request.getMethod() != HttpMethod.POST
                    || !PATHS.contains(request.getURI().getPath())) {
                return null;
            }
            if (!UUID.fromString(call.source().requestId()).toString().equals(call.source().requestId())) {
                return null;
            }
            String endpoint = request.getURI().getScheme() + "://" + request.getURI().getHost()
                    + (request.getURI().getPort() < 0 ? "" : ":" + request.getURI().getPort())
                    + request.getURI().getPath();
            return new ProviderExchangeCapture(call, endpoint, body, sanitizer, sink);
        } catch (RuntimeException unavailable) {
            log.warn("Provider capture unavailable: {}", unavailable.getClass().getSimpleName());
            return null;
        }
    }
}
