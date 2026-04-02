package io.contexa.contexaiam.security.xacml.pdp.combining;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for policy combining algorithm.
 * Default: FIRST_APPLICABLE (priority-ordered, first matching policy decides).
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "contexa.policy")
public class PolicyCombiningProperties {

    private CombiningAlgorithm combiningAlgorithm = CombiningAlgorithm.FIRST_APPLICABLE;
}
