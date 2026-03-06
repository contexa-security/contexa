package io.contexa.autoconfigure.core.infra;

import io.contexa.autoconfigure.properties.ContexaProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@AutoConfiguration
@ConditionalOnProperty(prefix = "contexa.infrastructure", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({ContexaProperties.class})
public class CoreInfrastructureExtendedAutoConfiguration {}
