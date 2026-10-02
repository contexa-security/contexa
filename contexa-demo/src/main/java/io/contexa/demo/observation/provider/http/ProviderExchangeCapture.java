package io.contexa.demo.observation.provider.http;

import io.contexa.demo.observation.model.call.ModelCallReference;
import io.contexa.demo.observation.provider.dto.ObservedProviderBody;
import io.contexa.demo.observation.provider.dto.ProviderHttpObservation;
import io.contexa.demo.observation.provider.service.ProviderBodySanitizer;
import io.contexa.demo.observation.provider.service.ProviderHttpSink;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.UUID;

public final class ProviderExchangeCapture {

    private static final Logger log = LoggerFactory.getLogger(ProviderExchangeCapture.class);
    private final UUID id = UUID.randomUUID();
    private final Instant startedAt = Instant.now();
    private final ModelCallReference call;
    private final String endpoint;
    private final ObservedProviderBody request;
    private final BoundedBodyCapture response = new BoundedBodyCapture();
    private final ProviderBodySanitizer sanitizer;
    private final ProviderHttpSink sink;
    private Integer status;
    private long expectedBytes = -1;
    private String failureType;
    private boolean finished;

    public ProviderExchangeCapture(ModelCallReference call, String endpoint, byte[] request,
            ProviderBodySanitizer sanitizer, ProviderHttpSink sink) {
        this.call = call;
        this.endpoint = endpoint;
        this.sanitizer = sanitizer;
        this.sink = sink;
        BoundedBodyCapture body = new BoundedBodyCapture();
        body.accept(request, 0, request.length);
        body.complete();
        this.request = body.finish(sanitizer, request.length);
    }

    public BoundedBodyCapture response() {
        return response;
    }

    public void status(int status) {
        this.status = status;
    }

    public void expectedBytes(long bytes) {
        expectedBytes = bytes;
    }

    public void failed(Exception failure) {
        failureType = failure.getClass().getSimpleName();
    }

    public void finish() {
        if (finished) {
            return;
        }
        finished = true;
        try {
            sink.offer(new ProviderHttpObservation(id, call, endpoint, "POST", startedAt, Instant.now(),
                    status, failureType, request, response.finish(sanitizer, expectedBytes)));
        } catch (RuntimeException unavailable) {
            log.warn("Provider observation missing: {}", unavailable.getClass().getSimpleName());
        }
    }
}
