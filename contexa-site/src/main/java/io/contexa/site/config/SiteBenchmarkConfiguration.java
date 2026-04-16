package io.contexa.site.config;

import io.contexa.contexacoreenterprise.benchmark.publication.BenchmarkPublicationCoreConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import(BenchmarkPublicationCoreConfiguration.class)
public class SiteBenchmarkConfiguration {
}