package io.contexa.autoconfigure.enterprise;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

/**
 * Enterprise JPA AutoConfiguration
 *
 * <p>
 * <strong>Enterprise Edition 전용</strong> - JPA Repository와 Entity 자동 구성
 * </p>
 *
 * <p>
 * Contexa Enterprise Edition의 JPA Repository와 Entity를 자동으로 스캔하여 등록합니다.
 * Community Edition과 독립적으로 작동하며, Enterprise 활성화 시에만 로드됩니다.
 * </p>
 *
 * <h3>활성화 조건:</h3>
 * <ul>
 *   <li>JPA가 클래스패스에 있을 때 (Jakarta Persistence EntityManager 존재)</li>
 *   <li>Enterprise Edition이 활성화되었을 때 (contexa.enterprise.enabled=true)</li>
 *   <li>Enterprise 클래스가 클래스패스에 있을 때 (ToolExecutionContextRepository)</li>
 * </ul>
 *
 * <h3>스캔 대상:</h3>
 * <h4>Repository (2개):</h4>
 * <ul>
 *   <li>contexa-core-enterprise: 2개 (io.contexa.contexacoreenterprise.repository)</li>
 *   <li>SynthesisPolicyRepository - 정책 합성</li>
 *   <li>ToolExecutionContextRepository - 도구 실행 컨텍스트</li>
 * </ul>
 *
 * <h4>Entity (1개):</h4>
 * <ul>
 *   <li>contexa-core-enterprise: 1개 (io.contexa.contexacoreenterprise.domain.entity)</li>
 *   <li>ToolExecutionContext - 도구 실행 컨텍스트 엔티티</li>
 * </ul>
 *
 * <h3>특징:</h3>
 * <ul>
 *   <li>조건부 로드: contexa.enterprise.enabled=true일 때만 활성화</li>
 *   <li>Community와 분리: Community JPA 설정과 독립적</li>
 *   <li>Spring Boot 3.x: Jakarta Persistence API 사용</li>
 *   <li>compileOnly 호환: @ConditionalOnClass에 문자열 사용</li>
 *   <li>별도 빈 등록 불필요: JPA Repository는 자동 생성됨</li>
 * </ul>
 *
 * <h3>설정 예시:</h3>
 * <pre>
 * contexa:
 *   enterprise:
 *     enabled: true  # Enterprise Edition 활성화
 * </pre>
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@ConditionalOnClass(name = {
    "io.contexa.contexacoreenterprise.repository.ToolExecutionContextRepository",
    "jakarta.persistence.EntityManager"
})
@ConditionalOnProperty(
    prefix = "contexa.enterprise",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = false
)
@EnableJpaRepositories(basePackages = {
    "io.contexa.contexacoreenterprise.repository"
})
@EntityScan(basePackages = {
    "io.contexa.contexacoreenterprise.domain.entity"
})
public class EnterpriseJpaAutoConfiguration {

    public EnterpriseJpaAutoConfiguration() {
        // JPA Repository는 Spring Data JPA가 자동으로 프록시 구현체를 생성하므로
        // 별도의 @Bean 메서드가 필요하지 않습니다.
        //
        // @EnableJpaRepositories와 @EntityScan만으로
        // 모든 Enterprise Repository와 Entity가 자동으로 등록됩니다.
        //
        // Community Edition과 독립적으로 작동하며,
        // contexa.enterprise.enabled=true일 때만 활성화됩니다.
    }
}
