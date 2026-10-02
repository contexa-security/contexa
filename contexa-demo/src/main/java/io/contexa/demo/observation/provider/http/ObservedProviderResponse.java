package io.contexa.demo.observation.provider.http;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpResponse;

import java.io.IOException;
import java.io.InputStream;

public final class ObservedProviderResponse implements ClientHttpResponse {

    private final ClientHttpResponse delegate;
    private final ProviderExchangeCapture capture;
    private InputStream stream;

    public ObservedProviderResponse(ClientHttpResponse delegate, ProviderExchangeCapture capture) {
        this.delegate = delegate;
        this.capture = capture;
    }

    @Override
    public HttpStatusCode getStatusCode() throws IOException {
        HttpStatusCode status = delegate.getStatusCode();
        capture.status(status.value());
        return status;
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
    public InputStream getBody() throws IOException {
        if (stream == null) {
            capture.expectedBytes(delegate.getHeaders().getContentLength());
            stream = new ObservedResponseStream(delegate.getBody(), capture.response(), capture::failed);
        }
        return stream;
    }

    @Override
    public void close() {
        try {
            delegate.close();
        } finally {
            capture.finish();
        }
    }
}
