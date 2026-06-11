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
package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.kafka.core.KafkaTemplate;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KafkaSecurityEventPublisherTest {

    @Mock
    private KafkaTemplate<String, Object> kafkaTemplate;

    @Test
    @DisplayName("본 publish 실패 시 DLQ dispatch 상태를 별도로 집계해야 한다")
    void shouldTrackDlqDispatchSeparatelyFromPrimaryPublishFailure() {
        SecurityKafkaProperties kafkaProperties = new SecurityKafkaProperties();
        KafkaSecurityEventPublisher publisher = new KafkaSecurityEventPublisher(kafkaTemplate, kafkaProperties);

        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("evt")
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType("METHOD")
                .userId("user-1")
                .sessionId("session-1")
                .clientIp("127.0.0.1")
                .payload(Map.of("action", "ALLOW"))
                .build();

        CompletableFuture<Object> failedFuture = new CompletableFuture<>();
        failedFuture.completeExceptionally(new IllegalStateException("publish failed"));
        when(kafkaTemplate.send(anyString(), anyString(), any()))
                .thenReturn((CompletableFuture) failedFuture);
        when(kafkaTemplate.send(anyString(), any()))
                .thenReturn(CompletableFuture.completedFuture(null));

        publisher.publishGenericSecurityEvent(event);

        assertThat(publisher.getStatistics())
                .containsEntry("publish_requested_count", 1L)
                .containsEntry("publish_failed_count", 1L)
                .containsEntry("dlq_dispatch_requested_count", 1L)
                .containsEntry("dlq_dispatch_confirmed_count", 1L)
                .containsEntry("dlq_dispatch_failed_count", 0L);
    }
}
