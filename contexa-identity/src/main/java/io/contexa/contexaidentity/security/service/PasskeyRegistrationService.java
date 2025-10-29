package io.contexa.contexaidentity.security.service;

import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.SecureRandom;

/**
 * Passkey 등록 서비스
 * <p>
 * 역할:
 * <ul>
 *   <li>WebAuthn UserEntity 생성 및 관리</li>
 *   <li>Passkey Credential 등록 후 데이터베이스 저장</li>
 *   <li>기존 사용자 시스템과 WebAuthn UserEntity 매핑</li>
 * </ul>
 * <p>
 * WebAuthn 표준에서 UserEntity는:
 * <ul>
 *   <li>name: 사용자명 (username, 고유)</li>
 *   <li>id: 32바이트 랜덤 바이너리 (User Handle, 사용자 식별용)</li>
 *   <li>displayName: 사용자 표시 이름</li>
 * </ul>
 *
 * @see org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository
 * @see org.springframework.security.web.webauthn.management.UserCredentialRepository
 * @since 2025-01
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PasskeyRegistrationService {

    private final UserCredentialRepository credentialRepository;
    private final PublicKeyCredentialUserEntityRepository userEntityRepository;

    /**
     * 사용자의 WebAuthn UserEntity 조회 또는 생성
     * <p>
     * Passkey 등록 전에 반드시 UserEntity가 존재해야 합니다.
     * 이미 존재하면 기존 것을 반환하고, 없으면 새로 생성합니다.
     *
     * @param username 사용자명
     * @return WebAuthn UserEntity
     */
    @Transactional
    public PublicKeyCredentialUserEntity getOrCreateUserEntity(String username) {
        return getOrCreateUserEntity(username, username);
    }

    /**
     * 사용자의 WebAuthn UserEntity 조회 또는 생성 (displayName 지정 가능)
     *
     * @param username 사용자명
     * @param displayName 표시 이름
     * @return WebAuthn UserEntity
     */
    @Transactional
    public PublicKeyCredentialUserEntity getOrCreateUserEntity(String username, String displayName) {
        // 1. 기존 UserEntity 조회
        PublicKeyCredentialUserEntity existingEntity = userEntityRepository.findByUsername(username);

        if (existingEntity != null) {
            log.debug("Existing UserEntity found for user: {}", username);
            return existingEntity;
        }

        // 2. 새로운 UserEntity 생성
        log.info("Creating new UserEntity for user: {}", username);

        // 32바이트 랜덤 User Handle 생성 (WebAuthn 표준 권장)
        byte[] userId = generateSecureUserId();

        // Spring Security API: ImmutablePublicKeyCredentialUserEntity builder 사용
        PublicKeyCredentialUserEntity newEntity = ImmutablePublicKeyCredentialUserEntity.builder()
            .name(username)
            .id(new Bytes(userId))
            .displayName(displayName)
            .build();

        // 3. 데이터베이스에 저장
        userEntityRepository.save(newEntity);

        log.info("UserEntity created successfully for user: {} (User Handle: {} bytes)",
                username, userId.length);

        return newEntity;
    }

    /**
     * 안전한 User ID 생성
     * <p>
     * WebAuthn 표준 권장사항:
     * <ul>
     *   <li>최소 32바이트 랜덤 값</li>
     *   <li>암호학적으로 안전한 난수 생성기 사용 (SecureRandom)</li>
     *   <li>사용자 개인정보 포함하지 않음</li>
     * </ul>
     *
     * @return 32바이트 랜덤 바이너리
     */
    private byte[] generateSecureUserId() {
        byte[] userId = new byte[32];
        new SecureRandom().nextBytes(userId);
        return userId;
    }

    /**
     * 등록된 Passkey 개수 조회
     * <p>
     * 사용자가 이미 Passkey를 등록했는지 확인할 때 사용
     *
     * @param username 사용자명
     * @return 등록된 Passkey 개수
     */
    public int getRegisteredPasskeyCount(String username) {
        PublicKeyCredentialUserEntity userEntity = userEntityRepository.findByUsername(username);

        if (userEntity == null) {
            return 0;
        }

        var credentials = credentialRepository.findByUserId(userEntity.getId());
        return credentials.size();
    }

    /**
     * 사용자가 Passkey를 등록했는지 확인
     *
     * @param username 사용자명
     * @return Passkey 등록 여부
     */
    public boolean hasRegisteredPasskey(String username) {
        return getRegisteredPasskeyCount(username) > 0;
    }

    /**
     * UserEntity 삭제 (테스트용)
     * <p>
     * ⚠️ 주의: UserEntity 삭제 시 연관된 모든 Credentials도 삭제됩니다 (CASCADE)
     *
     * @param username 사용자명
     */
    @Transactional
    public void deleteUserEntity(String username) {
        PublicKeyCredentialUserEntity userEntity = userEntityRepository.findByUsername(username);

        if (userEntity != null) {
            // Repository.delete()는 User ID (Bytes)를 받음
            userEntityRepository.delete(userEntity.getId());
            log.warn("⚠️ UserEntity deleted for user: {} (all credentials also deleted)", username);
        }
    }
}
