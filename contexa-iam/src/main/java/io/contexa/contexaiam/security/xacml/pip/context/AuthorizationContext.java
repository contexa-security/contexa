package io.contexa.contexaiam.security.xacml.pip.context;

import io.contexa.contexacommon.entity.Users;
import org.springframework.security.core.Authentication;

import java.util.Map;

/**
 * 인가 결정을 위해 필요한 모든 정보를 담는 표준화된 컨텍스트 객체.
 * 이 객체는 ContextHandler에 의해 생성되어 PolicyEngine으로 전달됩니다.
 */
public record AuthorizationContext(
        Authentication subject,    // 주체 (누가)
        Users subjectEntity,    // 실제 주체 (누가)
        ResourceDetails resource,    // 자원 (무엇을)
        String action,             // 행동 (어떻게)
        EnvironmentDetails environment, // 환경 (어떤 상황에서)
        Map<String, Object> attributes /* PIP를 통해 동적으로 로드된 추가 속성 */) { }
