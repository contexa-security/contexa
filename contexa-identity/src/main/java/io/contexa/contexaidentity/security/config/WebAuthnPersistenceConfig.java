package io.contexa.contexaidentity.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;

import lombok.extern.slf4j.Slf4j;

/**
 * WebAuthn/Passkey 영속성 설정
 * <p>
 * Spring Security 6.4+ JDBC Repository Bean 등록을 통한 Passkey 영속성 활성화
 * <p>
 * 역할:
 * <ul>
 *   <li>PublicKeyCredentialUserEntityRepository: passkey_users 테이블 관리</li>
 *   <li>UserCredentialRepository: user_credentials 테이블 관리</li>
 * </ul>
 * <p>
 * 필수 전제 조건:
 * <ul>
 *   <li>데이터베이스 스키마: user_entities, user_credentials 테이블 존재</li>
 *   <li>JdbcOperations Bean: Spring Boot JDBC Auto-configuration</li>
 * </ul>
 *
 * @see org.springframework.security.web.webauthn.management.JdbcPublicKeyCredentialUserEntityRepository
 * @see org.springframework.security.web.webauthn.management.JdbcUserCredentialRepository
 * @since 2025-01
 */
@Slf4j
@Configuration
public class WebAuthnPersistenceConfig {

    /**
     * User Entity Repository Bean 등록
     * <p>
     * user_entities 테이블에 WebAuthn UserEntity 저장/조회
     * <p>
     * UserEntity는 WebAuthn 프로토콜에서 사용자를 식별하는 엔티티:
     * <ul>
     *   <li>name: 사용자명 (고유)</li>
     *   <li>id: 32바이트 랜덤 바이너리 (User Handle)</li>
     *   <li>displayName: 사용자 표시 이름</li>
     * </ul>
     *
     * @param jdbcOperations Spring Boot가 자동 생성한 JdbcTemplate
     * @return Spring Security가 제공하는 JDBC 기반 Repository 구현체
     */
    @Bean
    public PublicKeyCredentialUserEntityRepository publicKeyCredentialUserEntityRepository(
            JdbcOperations jdbcOperations) {
        log.info("Initializing PublicKeyCredentialUserEntityRepository (JDBC-based)");
        return new JdbcPublicKeyCredentialUserEntityRepository(jdbcOperations);
    }

    /**
     * Credential Repository Bean 등록
     * <p>
     * user_credentials 테이블에 등록된 Passkey 저장/조회
     * <p>
     * CredentialRecord는 사용자가 등록한 Passkey 정보:
     * <ul>
     *   <li>credentialId: Credential의 고유 ID (바이너리)</li>
     *   <li>publicKey: 공개키 (바이너리)</li>
     *   <li>signatureCount: 서명 카운터 (리플레이 공격 방지)</li>
     *   <li>uvInitialized: User Verification 초기화 여부</li>
     *   <li>backedUp: 백업 여부 (동기화된 Passkey)</li>
     *   <li>transports: 지원하는 전송 방식 (USB, NFC, BLE, Internal)</li>
     * </ul>
     * <p>
     * Spring Security의 WebAuthn 인증 필터가 자동으로 이 Repository를 사용하여:
     * <ul>
     *   <li>인증 시: 사용자의 등록된 credentials 조회</li>
     *   <li>등록 시: 새로운 credential 저장</li>
     *   <li>검증 시: signature counter 업데이트</li>
     * </ul>
     *
     * @param jdbcOperations Spring Boot가 자동 생성한 JdbcTemplate
     * @return Spring Security가 제공하는 JDBC 기반 Repository 구현체
     */
    @Bean
    public UserCredentialRepository userCredentialRepository(
            JdbcOperations jdbcOperations) {
        log.info("Initializing UserCredentialRepository (JDBC-based)");
        return new JdbcUserCredentialRepository(jdbcOperations);
    }

    /**
     * 설정 검증 및 초기화 완료 로그
     * <p>
     * 이 Bean이 생성되면 Spring Security의 WebAuthn 필터들이
     * 자동으로 JDBC Repository를 사용하여 Passkey 인증을 처리합니다.
     */
    public WebAuthnPersistenceConfig() {
        log.info("🔑 WebAuthn Persistence Configuration initialized");
        log.info("   - User entities will be stored in: user_entities table");
        log.info("   - Credentials will be stored in: user_credentials table");
        log.info("   - Spring Security will automatically use JDBC repositories");
    }
}
