/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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
