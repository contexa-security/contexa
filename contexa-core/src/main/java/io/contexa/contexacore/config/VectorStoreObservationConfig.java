package io.contexa.contexacore.config;

import io.contexa.contexacore.std.rag.observation.SecurityVectorStoreObservationConvention;
import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.observation.DefaultMeterObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.vectorstore.observation.VectorStoreObservationConvention;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * VectorStore Observation 설정
 *
 * Spring AI VectorStore의 모든 작업을 자동으로 모니터링하고
 * OpenTelemetry 통합을 활성화합니다.
 *
 * 유기적 통합 전략:
 * 1. PgVectorStoreProperties가 자동으로 바인딩됨
 * 2. SecurityVectorStoreObservationConvention이 모든 VectorStore 작업에 적용됨
 * 3. PgVectorStore는 AbstractObservationVectorStore를 구현하고 있으므로
 *    VectorStoreObservationConvention Bean이 있으면 자동으로 사용됨
 * 4. 기존 코드(StandardVectorStoreService, AbstractVectorLabService 등) 수정 없이 자동 적용
 *
 * @since 1.0.0
 */
@Slf4j
@Configuration
@EnableConfigurationProperties(PgVectorStoreProperties.class)
@RequiredArgsConstructor
public class VectorStoreObservationConfig {

    private final PgVectorStoreProperties properties;
    private final ObservationRegistry observationRegistry;
    private final MeterRegistry meterRegistry;

    /**
     * 애플리케이션 시작 시 설정 로깅 및 ObservationHandler 수동 등록
     */
    @PostConstruct
    public void initialize() {
        log.info("=== PgVectorStoreProperties Configuration ===");
        log.info("  Index Type: {}", properties.getIndexType());
        log.info("  Distance Type: {}", properties.getDistanceType());
        log.info("  Dimensions: {}", properties.getDimensions());
        log.info("  Batch Size: {}", properties.getBatchSize());
        log.info("  Parallel Threads: {}", properties.getParallelThreads());
        log.info("  HNSW m: {}, ef_construction: {}, ef_search: {}",
            properties.getHnsw().getM(),
            properties.getHnsw().getEfConstruction(),
            properties.getHnsw().getEfSearch());

        // ⭐ ObservationRegistry 상태 확인
        log.info("=== ObservationRegistry Status (Before Handler Registration) ===");
        log.info("  ObservationRegistry Type: {}", observationRegistry.getClass().getSimpleName());
        log.info("  Is NOOP: {}", observationRegistry.isNoop());
        log.info("  MeterRegistry Type: {}", meterRegistry.getClass().getSimpleName());

        // ⭐ DefaultMeterObservationHandler 수동 등록
        DefaultMeterObservationHandler handler = new DefaultMeterObservationHandler(meterRegistry);
        observationRegistry.observationConfig().observationHandler(handler);

        log.info("=== ObservationRegistry Status (After Handler Registration) ===");
        log.info("  Is NOOP: {}", observationRegistry.isNoop());
        log.info("  Handler registered: {}", handler.getClass().getSimpleName());

        if (observationRegistry.isNoop()) {
            log.error("⚠️  ObservationRegistry is STILL NOOP after handler registration!");
        } else {
            log.info("✅ ObservationRegistry is active and ready for VectorStore metrics collection");
        }
    }

    /**
     * SecurityVectorStoreObservationConvention Bean
     *
     * Spring AI VectorStoreObservationConvention 구현체를 Bean으로 등록합니다.
     *
     * PgVectorStore는 AbstractObservationVectorStore를 구현하고 있으므로,
     * 이 Bean이 존재하면 자동으로 모든 VectorStore 작업에 적용됩니다.
     *
     * 자동 통합되는 컴포넌트:
     * - PgVectorStore: Spring AI가 자동으로 이 Convention 사용
     * - StandardVectorStoreService: VectorStore 주입 시 자동 모니터링
     * - AbstractVectorLabService: VectorStore 주입 시 자동 모니터링
     * - BehaviorVectorService, RiskAssessmentVectorService: Lab 작업 자동 추적
     * - HCADSimilarityCalculator: 위협 검색 자동 모니터링
     * - RagConfiguration, ContextRetriever: RAG 검색 자동 메트릭 수집
     *
     * @return VectorStoreObservationConvention
     */
    @Bean
    public VectorStoreObservationConvention securityVectorStoreObservationConvention() {
        log.info("=== Registering SecurityVectorStoreObservationConvention ===");
        log.info("PgVectorStore will automatically use this convention for all operations");
        return new SecurityVectorStoreObservationConvention();
    }

    /**
     * PgVectorStore Bean with ObservationRegistry
     *
     * PgVectorStoreAutoConfiguration보다 우선순위가 높은 Bean을 생성하여
     * ObservationRegistry를 명시적으로 주입합니다.
     *
     * @param jdbcTemplate JDBC Template
     * @param embeddingModel Embedding Model
     * @param observationConvention Observation Convention
     * @return PgVectorStore with ObservationRegistry
     */
    /*@Bean
    @Primary
    public VectorStore vectorStore(
            JdbcTemplate jdbcTemplate,
            EmbeddingModel embeddingModel,
            VectorStoreObservationConvention observationConvention) {

        log.info("=== Creating PgVectorStore with ObservationRegistry ===");
        log.info("ObservationRegistry Type: {}", observationRegistry.getClass().getSimpleName());
        log.info("ObservationRegistry isNoop: {}", observationRegistry.isNoop());

        PgVectorStore vectorStore = PgVectorStore.builder(jdbcTemplate, embeddingModel)
                .schemaName(properties.getSchemaName())
                .vectorTableName(properties.getTableName())
                .dimensions(properties.getDimensions())
                .distanceType(PgVectorStore.PgDistanceType.valueOf(properties.getDistanceType().name()))
                .removeExistingVectorStoreTable(properties.isRemoveExistingVectorStoreTable())
                .indexType(PgVectorStore.PgIndexType.valueOf(properties.getIndexType().name()))
                .initializeSchema(properties.isInitializeSchema())
                .observationRegistry(observationRegistry)  // ⭐ ObservationRegistry 주입
                .customObservationConvention(observationConvention)  // ⭐ Custom Convention 주입
                .build();

        log.info("✅ PgVectorStore created with ObservationRegistry successfully");
        return vectorStore;
    }*/
}
