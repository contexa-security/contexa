package io.contexa.contexacore.config;

import io.contexa.contexacore.properties.OpenTelemetryProperties;
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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class OpenTelemetryConfiguration {

    private final OpenTelemetryProperties openTelemetryProperties;

    @Bean
    public OpenTelemetry openTelemetry() {
        if (!openTelemetryProperties.isEnabled()) {
                        return OpenTelemetry.noop();
        }

        Resource resource = Resource.getDefault()
                .merge(Resource.create(Attributes.builder()
                        .put(ResourceAttributes.SERVICE_NAME, openTelemetryProperties.getServiceName())
                        .put(ResourceAttributes.SERVICE_VERSION, "1.0.0")
                        .put(ResourceAttributes.DEPLOYMENT_ENVIRONMENT, getEnvironment())
                        .build()));

        OtlpGrpcSpanExporter spanExporter = OtlpGrpcSpanExporter.builder()
                .setEndpoint(openTelemetryProperties.getExporterEndpoint())
                .setTimeout(10, TimeUnit.SECONDS)
                .build();

        BatchSpanProcessor batchSpanProcessor = BatchSpanProcessor.builder(spanExporter)
                .setMaxQueueSize(2048)
                .setMaxExportBatchSize(512)
                .setScheduleDelay(5, TimeUnit.SECONDS)
                .build();

        Sampler sampler = Sampler.traceIdRatioBased(openTelemetryProperties.getSamplingProbability());

        SdkTracerProvider tracerProvider = SdkTracerProvider.builder()
                .setResource(resource)
                .addSpanProcessor(batchSpanProcessor)
                .setSampler(sampler)
                .build();

        OpenTelemetrySdk openTelemetrySdk = OpenTelemetrySdk.builder()
                .setTracerProvider(tracerProvider)
                .setPropagators(ContextPropagators.create(W3CTraceContextPropagator.getInstance()))
                .buildAndRegisterGlobal();

        Runtime.getRuntime().addShutdownHook(new Thread(tracerProvider::close));

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
