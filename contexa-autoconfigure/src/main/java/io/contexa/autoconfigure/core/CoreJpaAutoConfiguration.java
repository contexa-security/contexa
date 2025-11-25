package io.contexa.autoconfigure.core;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

/**
 * Core JPA AutoConfiguration
 *
 * <p>
 * <strong>Community Edition</strong> - JPA Repository와 Entity 자동 구성
 * </p>
 *
 * <p>
 * Contexa Community Edition의 JPA Repository와 Entity를 자동으로 스캔하여 등록합니다.
 * 사용자 애플리케이션의 패키지와 독립적으로 작동하며, basePackages를 명시적으로 지정합니다.
 * </p>
 *
 * <h3>활성화 조건:</h3>
 * <ul>
 *   <li>JPA가 클래스패스에 있을 때 (Jakarta Persistence EntityManager 존재)</li>
 * </ul>
 *
 * <h3>스캔 대상:</h3>
 * <h4>Repository (32개 JpaRepository):</h4>
 * <ul>
 *   <li>contexa-common: 7개 (io.contexa.contexacommon.repository)</li>
 *   <li>contexa-core: 11개 (io.contexa.contexacore.repository)</li>
 *   <li>contexa-iam: 14개 (io.contexa.contexaiam.repository)</li>
 * </ul>
 *
 * <h4>비JPA Repository (스캔 제외):</h4>
 * <ul>
 *   <li>PolicyEvolutionProposalRepository - 메모리 기반 (ConcurrentHashMap)</li>
 *   <li>AIStrategySessionRepository - 세션 관리용 인터페이스</li>
 *   <li>MfaSessionRepository - 세션 관리용 인터페이스</li>
 * </ul>
 *
 * <h4>Entity (38개):</h4>
 * <ul>
 *   <li>contexa-common: 16개 (io.contexa.contexacommon.entity)</li>
 *   <li>contexa-core: 11개 (io.contexa.contexacore.domain.entity)</li>
 *   <li>contexa-iam: 11개 (io.contexa.contexaiam.domain.entity)</li>
 * </ul>
 *
 * <h3>주요 Repository:</h3>
 * <ul>
 *   <li>AuditLogRepository - 감사 로그</li>
 *   <li>UserRepository - 사용자 관리</li>
 *   <li>RoleRepository - 역할 관리</li>
 *   <li>PermissionRepository - 권한 관리</li>
 *   <li>PolicyRepository - 정책 관리</li>
 *   <li>ApprovalPolicyRepository - 승인 정책</li>
 *   <li>SecurityIncidentRepository - 보안 사고</li>
 * </ul>
 *
 * <h3>특징:</h3>
 * <ul>
 *   <li>basePackages 명시: 사용자 애플리케이션 패키지를 스캔하지 않음</li>
 *   <li>조건부 활성화: JPA가 없는 환경에서는 자동으로 비활성화</li>
 *   <li>Spring Boot 3.x: Jakarta Persistence API 사용</li>
 *   <li>Spring Boot 표준 패턴: @EnableJpaRepositories, @EntityScan 사용</li>
 *   <li>별도 빈 등록 불필요: JPA Repository는 자동 생성됨</li>
 * </ul>
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@ConditionalOnClass(name = "jakarta.persistence.EntityManager")
@EnableJpaRepositories(basePackages = {
    "io.contexa.contexacommon.repository",
    "io.contexa.contexacore.repository",
    "io.contexa.contexaiam.repository"
})
@EntityScan(basePackages = {
    "io.contexa.contexacommon.entity",
    "io.contexa.contexacore.domain.entity",
    "io.contexa.contexaiam.domain.entity"
})
public class CoreJpaAutoConfiguration {

    public CoreJpaAutoConfiguration() {
        // JPA Repository는 Spring Data JPA가 자동으로 프록시 구현체를 생성하므로
        // 별도의 @Bean 메서드가 필요하지 않습니다.
        //
        // @EnableJpaRepositories와 @EntityScan만으로
        // 모든 Repository와 Entity가 자동으로 등록됩니다.
    }
}
