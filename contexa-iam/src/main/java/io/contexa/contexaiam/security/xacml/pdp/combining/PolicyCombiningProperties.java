package io.contexa.contexaiam.security.xacml.pdp.combining;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for policy combining algorithm.
 * Default: DENY_OVERRIDES (most secure).
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "contexa.policy")
public class PolicyCombiningProperties {

    private CombiningAlgorithm combiningAlgorithm = CombiningAlgorithm.DENY_OVERRIDES;
}
