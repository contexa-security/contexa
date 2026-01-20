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


@Slf4j
@Configuration
public class OpenTelemetryConfiguration {

    @Value("${opentelemetry.service.name:contexa-core}")
    private String serviceName;

    @Value("${opentelemetry.traces.exporter.endpoint:http://localhost:4317}")
    private String otlpEndpoint;

    @Value("${opentelemetry.traces.sampler.probability:1.0}")
    private double samplingProbability;

    @Value("${opentelemetry.enabled:true}")
    private boolean enabled;

    
    @Bean
    public OpenTelemetry openTelemetry() {
        if (!enabled) {
            log.info("OpenTelemetry가 비활성화되어 있습니다. No-op 인스턴스를 반환합니다.");
            return OpenTelemetry.noop();
        }

        log.info("OpenTelemetry 초기화 시작 - Service: {}, Endpoint: {}, Sampling: {}",
                serviceName, otlpEndpoint, samplingProbability);

        
        Resource resource = Resource.getDefault()
                .merge(Resource.create(Attributes.builder()
                        .put(ResourceAttributes.SERVICE_NAME, serviceName)
                        .put(ResourceAttributes.SERVICE_VERSION, "1.0.0")
                        .put(ResourceAttributes.DEPLOYMENT_ENVIRONMENT, getEnvironment())
                        .build()));

        
        OtlpGrpcSpanExporter spanExporter = OtlpGrpcSpanExporter.builder()
                .setEndpoint(otlpEndpoint)
                .setTimeout(10, TimeUnit.SECONDS)
                .build();

        
        BatchSpanProcessor batchSpanProcessor = BatchSpanProcessor.builder(spanExporter)
                .setMaxQueueSize(2048)
                .setMaxExportBatchSize(512)
                .setScheduleDelay(5, TimeUnit.SECONDS)
                .build();

        
        Sampler sampler = Sampler.traceIdRatioBased(samplingProbability);

        
        SdkTracerProvider tracerProvider = SdkTracerProvider.builder()
                .setResource(resource)
                .addSpanProcessor(batchSpanProcessor)
                .setSampler(sampler)
                .build();

        
        OpenTelemetrySdk openTelemetrySdk = OpenTelemetrySdk.builder()
                .setTracerProvider(tracerProvider)
                .setPropagators(ContextPropagators.create(W3CTraceContextPropagator.getInstance()))
                .buildAndRegisterGlobal();

        
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("OpenTelemetry 종료 중...");
            tracerProvider.close();
            log.info("OpenTelemetry 종료 완료");
        }));

        log.info("OpenTelemetry 초기화 완료");
        return openTelemetrySdk;
    }

    
    @Bean
    public Tracer tracer(OpenTelemetry openTelemetry) {
        return openTelemetry.getTracer("io.contexa.contexacore");
    }

    
    private String getEnvironment() {
        String env = System.getenv("SPRING_PROFILES_ACTIVE");
        if (env == null || env.isEmpty()) {
            env = System.getProperty("spring.profiles.active", "development");
        }
        return env;
    }
}
