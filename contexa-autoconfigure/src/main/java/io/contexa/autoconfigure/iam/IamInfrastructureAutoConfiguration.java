package io.contexa.autoconfigure.iam;

import io.contexa.contexaiam.config.AppConfig;
import io.contexa.contexaiam.config.QuerydslConfig;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Import;

/**
 * IAM 인프라 AutoConfiguration
 *
 * Querydsl, WebClient 등 기본 인프라 설정
 */
@AutoConfiguration
@Import({
    QuerydslConfig.class,
    AppConfig.class
})
public class IamInfrastructureAutoConfiguration {
}
