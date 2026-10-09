package io.contexa.showcase.workload.contexa.observation;

import io.contexa.showcase.business.internal.InternalContextAttributes;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

/** Control D keeps when it received each signed request, on its own clock (fabricated-data survey #44). */
class RequestReceiptsTest {

    @Test
    void theFirstReceiptOfASignedRequestIsKeptAndUnsignedRequestsAreNot() throws Exception {
        Instant first = Instant.parse("2026-10-06T12:00:00Z");
        RequestReceipts receipts = new RequestReceipts(Clock.fixed(first, ZoneOffset.UTC));
        MockHttpServletRequest signed = new MockHttpServletRequest("GET", "/api/documents/X");
        signed.setAttribute(InternalContextAttributes.REQUEST_ID, "req-1");
        receipts.doFilter(signed, new MockHttpServletResponse(), new MockFilterChain());
        receipts.doFilter(new MockHttpServletRequest("GET", "/api/documents/X"), new MockHttpServletResponse(),
                new MockFilterChain());

        MockHttpServletRequest again = new MockHttpServletRequest("GET", "/api/documents/X");
        again.setAttribute(InternalContextAttributes.REQUEST_ID, "req-1");
        receipts.doFilter(again, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(receipts.receivedAt("req-1")).contains(first);
        assertThat(receipts.receivedAt("req-unknown")).isEmpty();
    }
}
