package io.contexa.contexaidentity.service;

import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class MfaSupportService { // 클래스명 변경

    private final UserRepository userRepository;

    /**
     * 사용자별 등록된 MFA Factor 조회.
     * MfaPolicyProvider 등에서 이 메소드를 호출하여 사용자의 MFA 설정을 가져옵니다.
     */
    public Set<AuthType> getRegisteredMfaFactorsForUser(String username) {
        Assert.hasText(username, "Username cannot be empty for fetching registered MFA factors");
        log.debug("MfaSupportService: Fetching registered MFA factors for user {}", username);

        return userRepository.findByUsernameWithGroupsRolesAndPermissions(username)
                .map(user -> {
                    if (!user.getMfaFactors().isEmpty()) {
                        try {
                            return user.getMfaFactors().stream()
                                    .map(String::trim)
                                    .map(String::toUpperCase)
                                    .map(AuthType::valueOf)
                                    .collect(Collectors.toCollection(() -> EnumSet.noneOf(AuthType.class)));
                        } catch (IllegalArgumentException e) {
                            log.warn("Invalid AuthType string found in mfaFactors for user {}: '{}'", username, user.getMfaFactors(), e);
                            return EnumSet.noneOf(AuthType.class);
                        }
                    }
                    return EnumSet.noneOf(AuthType.class);
                })
                .orElseGet(() -> {
                    log.warn("User {} not found for fetching registered MFA factors.", username);
                    return EnumSet.noneOf(AuthType.class);
                });
    }
}