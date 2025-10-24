package io.contexa.contexacore.config;

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.context.propagation.ContextPropagators;
import io.opentelemetry.exporter.otlp.trace.OtlpGrpcSpanExporter;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.resources.Resource;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.export.BatchSpanProcessor;
import io.opentelemetry.sdk.trace.samplers.Sampler;
import io.opentelemetry.semconv.ResourceAttributes;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

/**
 * OpenTelemetry 설정
 *
 * 분산 추적(Distributed Tracing)을 위한 OpenTelemetry 통합 설정입니다.
 * Jaeger, Zipkin 등의 백엔드로 trace 데이터를 전송할 수 있습니다.
 *
 * 주요 기능:
 * - 파이프라인 전체 실행 흐름 추적
 * - 각 단계별 소요 시간 측정
 * - 에러 발생 지점 및 컨텍스트 자동 수집
 * - Sampling 비율 조정으로 오버헤드 최소화
 */
@Slf4j
@Configuration
public class OpenTelemetryConfiguration {

    @Value("${opentelemetry.service.name:ai3security-aicore}")
    private String serviceName;

    @Value("${opentelemetry.traces.exporter.endpoint:http://localhost:4317}")
    private String otlpEndpoint;

    @Value("${opentelemetry.traces.sampler.probability:1.0}")
    private double samplingProbability;

    @Value("${opentelemetry.enabled:true}")
    private boolean enabled;

    /**
     * OpenTelemetry SDK 설정
     *
     * OTLP Exporter를 통해 Jaeger/Zipkin으로 trace 데이터를 전송합니다.
     */
    @Bean
    public OpenTelemetry openTelemetry() {
        if (!enabled) {
            log.info("OpenTelemetry가 비활성화되어 있습니다. No-op 인스턴스를 반환합니다.");
            return OpenTelemetry.noop();
        }

        log.info("OpenTelemetry 초기화 시작 - Service: {}, Endpoint: {}, Sampling: {}",
                serviceName, otlpEndpoint, samplingProbability);

        // Resource 정의: 서비스 식별 정보
        Resource resource = Resource.getDefault()
                .merge(Resource.create(Attributes.builder()
                        .put(ResourceAttributes.SERVICE_NAME, serviceName)
                        .put(ResourceAttributes.SERVICE_VERSION, "1.0.0")
                        .put(ResourceAttributes.DEPLOYMENT_ENVIRONMENT, getEnvironment())
                        .build()));

        // OTLP Exporter 설정: gRPC로 trace 데이터 전송
        OtlpGrpcSpanExporter spanExporter = OtlpGrpcSpanExporter.builder()
                .setEndpoint(otlpEndpoint)
                .setTimeout(10, TimeUnit.SECONDS)
                .build();

        // Batch Span Processor: 성능 최적화를 위해 배치로 전송
        BatchSpanProcessor batchSpanProcessor = BatchSpanProcessor.builder(spanExporter)
                .setMaxQueueSize(2048)
                .setMaxExportBatchSize(512)
                .setScheduleDelay(5, TimeUnit.SECONDS)
                .build();

        // Sampler 설정: Sampling 비율 조정으로 오버헤드 제어
        Sampler sampler = Sampler.traceIdRatioBased(samplingProbability);

        // TracerProvider 구성
        SdkTracerProvider tracerProvider = SdkTracerProvider.builder()
                .setResource(resource)
                .addSpanProcessor(batchSpanProcessor)
                .setSampler(sampler)
                .build();

        // OpenTelemetry SDK 빌드
        OpenTelemetrySdk openTelemetrySdk = OpenTelemetrySdk.builder()
                .setTracerProvider(tracerProvider)
                .setPropagators(ContextPropagators.create(W3CTraceContextPropagator.getInstance()))
                .buildAndRegisterGlobal();

        // Shutdown hook 등록: 애플리케이션 종료 시 리소스 정리
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("OpenTelemetry 종료 중...");
            tracerProvider.close();
            log.info("OpenTelemetry 종료 완료");
        }));

        log.info("OpenTelemetry 초기화 완료");
        return openTelemetrySdk;
    }

    /**
     * Tracer Bean 생성
     *
     * 각 컴포넌트에서 주입받아 사용할 Tracer 인스턴스를 제공합니다.
     */
    @Bean
    public Tracer tracer(OpenTelemetry openTelemetry) {
        return openTelemetry.getTracer("io.contexa.contexacore");
    }

    /**
     * 현재 실행 환경 감지
     */
    private String getEnvironment() {
        String env = System.getenv("SPRING_PROFILES_ACTIVE");
        if (env == null || env.isEmpty()) {
            env = System.getProperty("spring.profiles.active", "development");
        }
        return env;
    }
}
