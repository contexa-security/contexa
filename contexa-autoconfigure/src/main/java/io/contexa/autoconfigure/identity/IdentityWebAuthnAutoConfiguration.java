package io.contexa.autoconfigure.identity;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.web.webauthn.management.JdbcPublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.JdbcUserCredentialRepository;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;

/**
 * WebAuthn/Passkey 영속성 자동 설정
 *
 * Spring Security 6.4+ JDBC Repository Bean 자동 등록을 통한 Passkey 영속성 활성화
 *
 * 역할:
 * - PublicKeyCredentialUserEntityRepository: passkey_users 테이블 관리
 * - UserCredentialRepository: user_credentials 테이블 관리
 *
 * 필수 전제 조건:
 * - 데이터베이스 스키마: user_entities, user_credentials 테이블 존재
 * - JdbcOperations Bean: Spring Boot JDBC Auto-configuration
 *
 * @since 2025-01
 */
@Slf4j
@AutoConfiguration
public class IdentityWebAuthnAutoConfiguration {

    /**
     * User Entity Repository Bean 자동 등록
     *
     * user_entities 테이블에 WebAuthn UserEntity 저장/조회
     *
     * UserEntity는 WebAuthn 프로토콜에서 사용자를 식별하는 엔티티:
     * - name: 사용자명 (고유)
     * - id: 32바이트 랜덤 바이너리 (User Handle)
     * - displayName: 사용자 표시 이름
     *
     * @param jdbcOperations Spring Boot가 자동 생성한 JdbcTemplate
     * @return Spring Security가 제공하는 JDBC 기반 Repository 구현체
     */
    @Bean
    @ConditionalOnMissingBean(PublicKeyCredentialUserEntityRepository.class)
    public PublicKeyCredentialUserEntityRepository publicKeyCredentialUserEntityRepository(
            JdbcOperations jdbcOperations) {
        log.info("Initializing PublicKeyCredentialUserEntityRepository (JDBC-based)");
        return new JdbcPublicKeyCredentialUserEntityRepository(jdbcOperations);
    }

    /**
     * Credential Repository Bean 자동 등록
     *
     * user_credentials 테이블에 등록된 Passkey 저장/조회
     *
     * CredentialRecord는 사용자가 등록한 Passkey 정보:
     * - credentialId: Credential의 고유 ID (바이너리)
     * - publicKey: 공개키 (바이너리)
     * - signatureCount: 서명 카운터 (리플레이 공격 방지)
     * - uvInitialized: User Verification 초기화 여부
     * - backedUp: 백업 여부 (동기화된 Passkey)
     * - transports: 지원하는 전송 방식 (USB, NFC, BLE, Internal)
     *
     * Spring Security의 WebAuthn 인증 필터가 자동으로 이 Repository를 사용하여:
     * - 인증 시: 사용자의 등록된 credentials 조회
     * - 등록 시: 새로운 credential 저장
     * - 검증 시: signature counter 업데이트
     *
     * @param jdbcOperations Spring Boot가 자동 생성한 JdbcTemplate
     * @return Spring Security가 제공하는 JDBC 기반 Repository 구현체
     */
    @Bean
    @ConditionalOnMissingBean(UserCredentialRepository.class)
    public UserCredentialRepository userCredentialRepository(
            JdbcOperations jdbcOperations) {
        log.info("Initializing UserCredentialRepository (JDBC-based)");
        return new JdbcUserCredentialRepository(jdbcOperations);
    }

    /**
     * 설정 검증 및 초기화 완료 로그
     *
     * 이 Bean이 생성되면 Spring Security의 WebAuthn 필터들이
     * 자동으로 JDBC Repository를 사용하여 Passkey 인증을 처리합니다.
     */
    public IdentityWebAuthnAutoConfiguration() {
        log.info("WebAuthn Persistence Configuration initialized");
        log.info("   - User entities will be stored in: user_entities table");
        log.info("   - Credentials will be stored in: user_credentials table");
        log.info("   - Spring Security will automatically use JDBC repositories");
    }
}
