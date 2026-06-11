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
package io.contexa.contexacore.std.operations;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.std.components.event.AuditLogger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AINativeProcessorTest {

    @Mock
    private AuditLogger auditLogger;

    @Mock
    private DistributedLockService distributedLockService;

    @Mock
    private DistributedStrategyExecutor<TestContext> distributedStrategyExecutor;

    @Test
    void processShouldUseStableStrategicLockKeyForSameSemanticRequest() {
        AINativeProcessor<TestContext> processor = new AINativeProcessor<>(
                auditLogger,
                distributedLockService,
                distributedStrategyExecutor);
        AIRequest<TestContext> request = new AIRequest<>(
                new TestContext("user-1", "session-1", "tenant-a"),
                new TemplateType("standard"),
                new DiagnosisType("general"));
        request.setNaturalLanguageQuery("summarize risk");
        request.withParameter("purpose", "security");

        when(distributedLockService.tryLock(any(), any(), any(Duration.class))).thenReturn(true);
        when(auditLogger.startAudit(request)).thenReturn("audit-1");
        when(distributedStrategyExecutor.executeDistributedStrategyAsync(request, TestResponse.class))
                .thenReturn(Mono.just(new TestResponse()));

        processor.process(request, TestResponse.class).block();
        processor.process(request, TestResponse.class).block();

        ArgumentCaptor<String> lockKeyCaptor = ArgumentCaptor.forClass(String.class);
        verify(distributedLockService, times(2))
                .tryLock(lockKeyCaptor.capture(), any(), eq(Duration.ofMinutes(30)));
        assertThat(lockKeyCaptor.getAllValues()).hasSize(2);
        assertThat(lockKeyCaptor.getAllValues().get(0)).isEqualTo(lockKeyCaptor.getAllValues().get(1));
    }

    private static final class TestContext extends DomainContext {
        private TestContext(String userId, String sessionId, String organizationId) {
            setUserId(userId);
            setSessionId(sessionId);
            setOrganizationId(organizationId);
        }

        @Override
        public String getDomainType() {
            return "test";
        }
    }

    private static final class TestResponse extends AIResponse {
    }
}
