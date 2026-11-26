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
package io.contexa.contexacore.std.llm.client;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.Prompt;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R-9: an instance counts as Contexa's only as itself. An application's chat model whose class says it equals one of
 * Contexa's instances is still the application's, and Contexa sets nothing in its defaults.
 */
@DisplayName("Contexa 채팅 모델 인스턴스 기록은 같은 객체만 인정한다")
class ContexaChatModelInstancesTest {

    @Test
    @DisplayName("Contexa 인스턴스와 equals로 같은 앱 모델은 Contexa 인스턴스가 아니다")
    void aModelThatEqualsContexasInstanceIsNotContexas() {
        EqualToEveryOther contexas = ContexaChatModelInstances.add(new EqualToEveryOther());
        EqualToEveryOther applications = new EqualToEveryOther();

        assertThat(applications).isEqualTo(contexas);
        assertThat(ContexaChatModelInstances.isContexas(contexas)).isTrue();
        assertThat(ContexaChatModelInstances.isContexas(applications)).isFalse();
    }

    /** A chat model class that equals every other instance of itself. */
    private static final class EqualToEveryOther implements ChatModel {

        @Override
        public ChatResponse call(Prompt prompt) {
            throw new UnsupportedOperationException("not called");
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof EqualToEveryOther;
        }

        @Override
        public int hashCode() {
            return 1;
        }
    }
}
