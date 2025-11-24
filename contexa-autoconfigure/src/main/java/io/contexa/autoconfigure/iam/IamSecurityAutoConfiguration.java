package io.contexa.autoconfigure.iam;

import io.contexa.contexaiam.config.MySecurityConfig;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Import;

/**
 * IAM Security AutoConfiguration
 *
 * Spring Security FilterChain, MethodSecurity 설정
 */
@AutoConfiguration
@Import(MySecurityConfig.class)
public class IamSecurityAutoConfiguration {
}
