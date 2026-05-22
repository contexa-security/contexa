package io.contexa.contexacore.std.advisor.core;

import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.chat.client.ChatClientResponse;
import org.springframework.ai.chat.client.advisor.api.CallAdvisor;
import org.springframework.ai.chat.client.advisor.api.CallAdvisorChain;
import org.springframework.ai.chat.prompt.Prompt;

import java.util.HashMap;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BaseAdvisorTest {

    @Test
    void adviseCallShouldNotInvokeExhaustedChainAgainWhenDownstreamCallFails() {
        RuntimeException downstreamFailure = new RuntimeException("HTTP 400 - unsupported max_tokens");
        CountingFailingChain chain = new CountingFailingChain(downstreamFailure);
        TestAdvisor advisor = new TestAdvisor();
        ChatClientRequest request = new ChatClientRequest(new Prompt("security prompt"), new HashMap<>());

        assertThatThrownBy(() -> advisor.adviseCall(request, chain))
                .isSameAs(downstreamFailure);

        assertThat(chain.calls).isEqualTo(1);
        assertThat(request.context()).containsEntry("SECURITY.security-context.error", downstreamFailure.getMessage());
    }

    private static final class TestAdvisor extends BaseAdvisor {

        private TestAdvisor() {
            super("SECURITY", "security-context", 0);
        }

        @Override
        protected ChatClientRequest beforeCall(ChatClientRequest request) {
            return request;
        }

        @Override
        protected ChatClientResponse afterCall(ChatClientResponse response, ChatClientRequest request) {
            return response;
        }
    }

    private static final class CountingFailingChain implements CallAdvisorChain {

        private final RuntimeException failure;
        private int calls;

        private CountingFailingChain(RuntimeException failure) {
            this.failure = failure;
        }

        @Override
        public ChatClientResponse nextCall(ChatClientRequest request) {
            calls++;
            throw failure;
        }

        @Override
        public List<CallAdvisor> getCallAdvisors() {
            return List.of();
        }

        @Override
        public CallAdvisorChain copy(CallAdvisor advisor) {
            return this;
        }
    }
}
