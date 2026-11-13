package io.contexa.contexaiam.aiam.web;

import io.contexa.contexaiam.aiam.event.ZeroTrustSsePublisher;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * IAM-D04: a client that left the analysis page breaks its stream. The failed write comes back to the subscription on
 * the async dispatch; it is the normal end of the subscription and is answered quietly, not thrown to the container
 * (which logged it as a servlet ERROR with a stack).
 */
class ZeroTrustSseControllerTest {

    private static final String SUBSCRIBE = "/contexa/admin/api/aiam/sse/zero-trust/subscribe";

    @Test
    void aStreamTheClientClosedEndsWithoutAServerError() throws Exception {
        AtomicReference<SseEmitter> subscribed = new AtomicReference<>();
        ZeroTrustSsePublisher publisher = new ZeroTrustSsePublisher() {
            @Override
            public SseEmitter addEmitter(String userId) {
                SseEmitter emitter = super.addEmitter(userId);
                subscribed.set(emitter);
                return emitter;
            }
        };
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new ZeroTrustSseController(publisher)).build();

        MvcResult result = mvc.perform(get(SUBSCRIBE).principal(new TestingAuthenticationToken("alice", "n/a")))
                .andExpect(request().asyncStarted())
                .andReturn();
        subscribed.get().completeWithError(new IOException("An established connection was aborted"));

        mvc.perform(asyncDispatch(result)).andExpect(status().isOk());
    }
}
