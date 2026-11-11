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
package io.contexa.autoconfigure.core.autonomous;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacore.autonomous.saas.PromptContextAuditRecorder;
import io.contexa.contexacore.autonomous.saas.SaasBaselineSeedService;
import io.contexa.contexacore.autonomous.saas.SaasDetectionStrategyPackService;
import io.contexa.contexacore.autonomous.saas.SaasThreatIntelligenceService;
import io.contexa.contexacore.autonomous.saas.SaasThreatKnowledgePackService;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.strategy.AbstractTieredStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.security.AuthorizedPromptContext;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import io.contexa.contexacore.util.ErrorLogThrottle;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * An analysis whose event names no user skips its RAG search, so records of one account never reach the decision of
 * another. The skip is the same for every such request; its ERROR line is written for the first one and then at most
 * once per interval with the number of skips that were not written. The strategy is the one Contexa's auto-configuration
 * creates, in a Spring context; the vector store and the model are stand-ins, so the search is seen as it is asked.
 */
class AnalysesWithoutAUserIdLogTest {

    private static final String RAG_SEARCH_SKIPPED = "userId missing - skipping RAG search for account isolation";
    private static final String PAST_RECORD_LOOKUP_SKIPPED =
            "userId missing - skipping the past record lookup for account isolation";
    private static final Duration REPORT_INTERVAL = Duration.ofMinutes(5);
    private static final String[] NO_USER = {null, "", "unknown"};

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(TheStrategyOfTheAutoConfiguration.class)
            .withBean(UnifiedVectorService.class, () -> mock(UnifiedVectorService.class))
            .withBean(SecurityContextDataStore.class, () -> mock(SecurityContextDataStore.class))
            .withBean(SecurityEventEnricher.class, AnalysesWithoutAUserIdLogTest::enricher)
            .withBean(SecurityDecisionStandardPromptTemplate.class, () -> mock(SecurityDecisionStandardPromptTemplate.class))
            .withBean(BehaviorVectorService.class, () -> mock(BehaviorVectorService.class))
            .withBean(BaselineLearningService.class, () -> mock(BaselineLearningService.class))
            .withBean(SecurityLearningService.class, () -> mock(SecurityLearningService.class))
            .withBean(PromptContextAuthorizationService.class, () -> mock(PromptContextAuthorizationService.class))
            .withBean(PromptContextAuditRecorder.class, () -> mock(PromptContextAuditRecorder.class))
            .withBean(StructuredOutputCapabilityRegistry.class, StructuredOutputCapabilityRegistry::defaultRegistry)
            .withBean(TieredStrategyProperties.class, TieredStrategyProperties::new)
            .withBean(SecurityZeroTrustProperties.class, SecurityZeroTrustProperties::new);

    @Test
    @DisplayName("Twenty analyses without a user log the skipped RAG search once and still skip every search")
    void analysesWithoutAUserLogTheSkippedSearchOnce() {
        contextRunner.run(context -> {
            Layer1ContextualStrategy strategy = context.getBean(Layer1ContextualStrategy.class);
            UnifiedVectorService vectors = context.getBean(UnifiedVectorService.class);
            PromptContextAuditRecorder audit = context.getBean(PromptContextAuditRecorder.class);

            List<SecurityEvent> withoutAUser = new ArrayList<>();
            List<String> errors = errorsDuring(() -> {
                for (int index = 0; index < 20; index++) {
                    SecurityEvent event = event("no-user-" + index, NO_USER[index % NO_USER.length]);
                    strategy.analyzeWithContext(event);
                    withoutAUser.add(event);
                }
            });

            assertThat(errors).filteredOn(line -> line.contains(RAG_SEARCH_SKIPPED)).hasSize(1);
            verify(vectors, never()).searchSimilar(any(SearchRequest.class));
            assertThat(withoutAUser).allSatisfy(event -> assertThat(event.getMetadata())
                    .containsEntry("ragAbsenceReason", "USER_ID_MISSING")
                    .containsEntry("ragRetrievalState", "NOT_REQUESTED"));
            verify(audit, times(20)).capture(any(SecurityEvent.class), any(),
                    argThat(AnalysesWithoutAUserIdLogTest::deniedForTheMissingUser));
        });
    }

    @Test
    @DisplayName("Analyses that name their user write no such line and still search the user's own records")
    void analysesThatNameTheirUserAreUnchanged() {
        contextRunner.run(context -> {
            Layer1ContextualStrategy strategy = context.getBean(Layer1ContextualStrategy.class);
            UnifiedVectorService vectors = context.getBean(UnifiedVectorService.class);
            PromptContextAuditRecorder audit = context.getBean(PromptContextAuditRecorder.class);

            List<SecurityEvent> named = new ArrayList<>();
            List<String> errors = errorsDuring(() -> {
                for (int index = 0; index < 5; index++) {
                    SecurityEvent event = event("alice-" + index, "alice");
                    strategy.analyzeWithContext(event);
                    named.add(event);
                }
            });

            assertThat(errors).noneMatch(line -> line.contains("userId missing"));
            verify(vectors, atLeastOnce()).searchSimilar(any(SearchRequest.class));
            assertThat(named).allSatisfy(event -> assertThat(event.getMetadata().get("ragAbsenceReason"))
                    .isNotEqualTo("USER_ID_MISSING"));
            verify(audit, never()).capture(any(SecurityEvent.class), any(),
                    argThat(AnalysesWithoutAUserIdLogTest::deniedForTheMissingUser));
        });
    }

    @Test
    @DisplayName("After the interval the next skip is written with the number of skips that were not")
    void theNextLineCarriesTheSkipsThatWereNotWritten() {
        contextRunner.run(context -> {
            Layer1ContextualStrategy strategy = context.getBean(Layer1ContextualStrategy.class);
            AtomicLong now = new AtomicLong(1_000_000L);
            ReflectionTestUtils.setField(strategy, AbstractTieredStrategy.class, "missingUserIdRagSearchLog",
                    new ErrorLogThrottle(REPORT_INTERVAL, now::get), ErrorLogThrottle.class);

            List<String> errors = errorsDuring(() -> {
                for (int index = 0; index < 20; index++) {
                    strategy.analyzeWithContext(event("first-" + index, "unknown"));
                }
                now.addAndGet(REPORT_INTERVAL.toMillis());
                strategy.analyzeWithContext(event("after-the-interval", "unknown"));
            });

            List<String> written = errors.stream().filter(line -> line.contains(RAG_SEARCH_SKIPPED)).toList();
            assertThat(written).hasSize(2);
            assertThat(written.get(0)).contains("similarSinceLastReport=0");
            assertThat(written.get(1)).contains("similarSinceLastReport=19");
        });
    }

    @Test
    @DisplayName("The exact past-record lookup of a v20 analysis without a user is skipped every time and written once")
    void theExactPastRecordLookupWithoutAUserIsWrittenOnce() {
        contextRunner.run(context -> {
            Layer1ContextualStrategy strategy = context.getBean(Layer1ContextualStrategy.class);
            UnifiedVectorService vectors = context.getBean(UnifiedVectorService.class);
            SecurityDecisionStandardPromptTemplate template = context.getBean(SecurityDecisionStandardPromptTemplate.class);
            when(template.promptBundle(any(SecurityEvent.class))).thenReturn(SecurityDecisionPromptBundles.V20);

            List<SecurityEvent> withoutAUser = new ArrayList<>();
            List<String> errors = errorsDuring(() -> {
                for (int index = 0; index < 20; index++) {
                    SecurityEvent event = event("v20-no-user-" + index, NO_USER[index % NO_USER.length]);
                    strategy.analyzeWithContext(event);
                    withoutAUser.add(event);
                }
            });

            assertThat(errors).filteredOn(line -> line.contains(PAST_RECORD_LOOKUP_SKIPPED)).hasSize(1);
            assertThat(errors).noneMatch(line -> line.contains(RAG_SEARCH_SKIPPED));
            verify(vectors, never()).pastRecordQuery();
            assertThat(withoutAUser).allSatisfy(event -> assertThat(event.getMetadata())
                    .containsEntry("ragAbsenceReason", "USER_ID_MISSING"));

            clearInvocations(vectors);
            strategy.analyzeWithContext(event("v20-alice", "alice"));
            verify(vectors, times(1)).pastRecordQuery();
        });
    }

    private static boolean deniedForTheMissingUser(AuthorizedPromptContext context) {
        return context != null && context.deniedReasons() != null && context.deniedReasons().contains("USER_ID_MISSING");
    }

    private static SecurityEventEnricher enricher() {
        SecurityEventEnricher enricher = mock(SecurityEventEnricher.class);
        when(enricher.getTargetResource(any(SecurityEvent.class))).thenReturn(Optional.of("/h/weird/orders"));
        return enricher;
    }

    private static SecurityEvent event(String id, String userId) {
        return SecurityEvent.builder()
                .eventId(id)
                .userId(userId)
                .sourceIp("192.168.1.100")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                .metadata(new LinkedHashMap<>())
                .build();
    }

    /** The ERROR lines the tiered strategies write while the work runs, on whichever thread writes them. */
    private static List<String> errorsDuring(Runnable work) {
        Logger logger = (Logger) LoggerFactory.getLogger(AbstractTieredStrategy.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            work.run();
        } finally {
            logger.detachAppender(appender);
        }
        return appender.list.stream()
                .filter(line -> line.getLevel() == Level.ERROR)
                .map(ILoggingEvent::getFormattedMessage)
                .toList();
    }

    /** The Layer 1 strategy as {@link CoreAutonomousAutoConfiguration} creates it, with its own RAG executor. */
    @Configuration(proxyBeanMethods = false)
    static class TheStrategyOfTheAutoConfiguration {

        private final CoreAutonomousAutoConfiguration configuration = new CoreAutonomousAutoConfiguration();

        @Bean(name = "contexaLayer1RagRetrievalExecutor", destroyMethod = "shutdown")
        ExecutorService contexaLayer1RagRetrievalExecutor() {
            return configuration.layer1RagRetrievalExecutor();
        }

        @Bean(name = "contexaContextualStrategy")
        Layer1ContextualStrategy contexaContextualStrategy(
                UnifiedVectorService unifiedVectorService,
                SecurityContextDataStore dataStore,
                SecurityEventEnricher securityEventEnricher,
                SecurityDecisionStandardPromptTemplate promptTemplate,
                BehaviorVectorService behaviorVectorService,
                BaselineLearningService baselineLearningService,
                SecurityLearningService securityLearningService,
                ObjectProvider<SaasBaselineSeedService> baselineSeedService,
                ObjectProvider<SaasThreatIntelligenceService> threatIntelligenceService,
                ObjectProvider<SaasThreatKnowledgePackService> threatKnowledgePackService,
                ObjectProvider<SaasDetectionStrategyPackService> detectionStrategyPackService,
                ObjectProvider<PromptContextAuditRecorder> promptContextAuditRecorder,
                PromptContextAuthorizationService promptContextAuthorizationService,
                ObjectProvider<PipelineOrchestrator> pipelineOrchestrator,
                StructuredOutputCapabilityRegistry structuredOutputCapabilityRegistry,
                @Qualifier("contexaLayer1RagRetrievalExecutor") ExecutorService ragRetrievalExecutor,
                TieredStrategyProperties tieredStrategyProperties,
                SecurityZeroTrustProperties securityZeroTrustProperties,
                ObjectProvider<ModelSelectionStrategy> modelSelectionStrategy) {
            return configuration.contextualStrategy(unifiedVectorService, dataStore, securityEventEnricher,
                    promptTemplate, behaviorVectorService, baselineLearningService, securityLearningService,
                    baselineSeedService, threatIntelligenceService, threatKnowledgePackService,
                    detectionStrategyPackService, promptContextAuditRecorder, promptContextAuthorizationService,
                    pipelineOrchestrator, structuredOutputCapabilityRegistry, ragRetrievalExecutor,
                    tieredStrategyProperties, securityZeroTrustProperties, modelSelectionStrategy);
        }
    }
}
