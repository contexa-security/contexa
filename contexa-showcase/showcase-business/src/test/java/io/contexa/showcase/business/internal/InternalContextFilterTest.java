package io.contexa.showcase.business.internal;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

class InternalContextFilterTest {

    private static final Instant NOW = Instant.parse("2026-10-04T12:00:00Z");
    private static final String KEY = randomKey();
    private static final InternalContext CONTEXT = new InternalContext(
            "run-1", "req-1", Instant.parse("2026-09-28T23:40:00Z"), "10.20.30.41",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "org-run-1", "tenant-run-1");

    private final InternalContextSigner signer = new InternalContextSigner(KEY);
    private final InternalContextFilter filter = new InternalContextFilter(
            signer, Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofSeconds(60));

    @Test
    void verifiedContextBecomesEngineAttributesAndClientView() throws Exception {
        MockHttpServletRequest request = signedRequest(CONTEXT, NOW.getEpochSecond(), KEY);
        request.addHeader("X-Request-ID", "client-chosen");
        request.addHeader("X-Forwarded-For", "203.0.113.9");
        request.addHeader("X-Contexa-Anomaly-Signal", "true");

        HttpServletRequest seen = run(request);

        assertThat(request.getAttribute(InternalContextAttributes.CONTEXT)).isEqualTo(CONTEXT);
        assertThat(request.getAttribute(InternalContextAttributes.OBSERVED_AT)).isEqualTo(CONTEXT.observedAt());
        assertThat(request.getAttribute(InternalContextAttributes.ORGANIZATION_ID)).isEqualTo("org-run-1");
        assertThat(request.getAttribute(InternalContextAttributes.TENANT_ID)).isEqualTo("tenant-run-1");
        assertThat(request.getAttribute(InternalContextAttributes.REQUEST_ID)).isEqualTo("req-1");
        assertThat(seen.getRemoteAddr()).isEqualTo("10.20.30.41");
        assertThat(seen.getHeader("User-Agent")).isEqualTo(CONTEXT.device());
        assertThat(seen.getHeader("X-Request-ID")).isNull();
        assertThat(seen.getHeader("X-Forwarded-For")).isNull();
        assertThat(seen.getHeader("X-Contexa-Anomaly-Signal")).isNull();
        assertThat(seen.getHeader(InternalContextHeaders.SIGNATURE)).isNull();
        assertThat(Collections.list(seen.getHeaderNames()))
                .noneMatch(name -> name.toLowerCase().startsWith("x-showcase-"))
                .contains("User-Agent");
    }

    @Test
    void signatureFromAnotherKeyIsIgnored() throws Exception {
        MockHttpServletRequest request = signedRequest(CONTEXT, NOW.getEpochSecond(), randomKey());

        HttpServletRequest seen = run(request);

        assertNoContext(request, seen);
    }

    @Test
    void tamperedValueIsIgnored() throws Exception {
        MockHttpServletRequest request = signedRequest(CONTEXT, NOW.getEpochSecond(), KEY);
        request.removeHeader(InternalContextHeaders.ORGANIZATION);
        request.addHeader(InternalContextHeaders.ORGANIZATION, "org-other-run");

        HttpServletRequest seen = run(request);

        assertNoContext(request, seen);
    }

    @Test
    void staleTimestampIsIgnored() throws Exception {
        MockHttpServletRequest request = signedRequest(CONTEXT, NOW.getEpochSecond() - 61, KEY);

        HttpServletRequest seen = run(request);

        assertNoContext(request, seen);
    }

    @Test
    void unsignedRequestKeepsItsOwnClientButLosesTrustedHeaders() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/work/documents/7");
        request.setRemoteAddr("172.18.0.5");
        request.addHeader("X-Request-ID", "client-chosen");
        request.addHeader("X-Real-IP", "203.0.113.9");
        request.addHeader("User-Agent", "curl/8");

        HttpServletRequest seen = run(request);

        assertNoContext(request, seen);
        assertThat(seen.getRemoteAddr()).isEqualTo("172.18.0.5");
        assertThat(seen.getHeader("User-Agent")).isEqualTo("curl/8");
        assertThat(seen.getHeader("X-Real-IP")).isNull();
    }

    @Test
    void signatureCoversTheQueryString() throws Exception {
        MockHttpServletRequest request = signedRequest(CONTEXT, NOW.getEpochSecond(), KEY);
        request.setQueryString("limit=5000");

        HttpServletRequest seen = run(request);

        assertNoContext(request, seen);
    }

    private HttpServletRequest run(MockHttpServletRequest request) throws Exception {
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);
        return (HttpServletRequest) chain.getRequest();
    }

    private static void assertNoContext(MockHttpServletRequest request, HttpServletRequest seen) {
        assertThat(request.getAttribute(InternalContextAttributes.CONTEXT)).isNull();
        assertThat(request.getAttribute(InternalContextAttributes.ORGANIZATION_ID)).isNull();
        assertThat(request.getAttribute(InternalContextAttributes.OBSERVED_AT)).isNull();
        assertThat(request.getAttribute(InternalContextAttributes.REQUEST_ID)).isNull();
        assertThat(seen.getHeader("X-Request-ID")).isNull();
        assertThat(seen.getRemoteAddr()).isNotEqualTo(CONTEXT.clientIp());
    }

    private static MockHttpServletRequest signedRequest(InternalContext context, long timestamp, String key) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/work/documents/7");
        request.setRemoteAddr("172.18.0.5");
        request.addHeader("User-Agent", "Java-http-client/17");
        request.addHeader(InternalContextHeaders.RUN, context.runId());
        request.addHeader(InternalContextHeaders.REQUEST_ID, context.requestId());
        request.addHeader(InternalContextHeaders.OBSERVED_AT, context.observedAt().toString());
        request.addHeader(InternalContextHeaders.CLIENT_IP, context.clientIp());
        request.addHeader(InternalContextHeaders.DEVICE, context.device());
        request.addHeader(InternalContextHeaders.ORGANIZATION, context.organization());
        request.addHeader(InternalContextHeaders.TENANT, context.tenant());
        request.addHeader(InternalContextHeaders.TIMESTAMP, Long.toString(timestamp));
        request.addHeader(InternalContextHeaders.SIGNATURE,
                new InternalContextSigner(key).sign("GET", "/work/documents/7", timestamp, context));
        return request;
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
