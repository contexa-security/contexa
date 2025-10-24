package io.contexa.contexaiam.security.xacml.pip.context;

import io.contexa.contexaiam.security.core.CustomUserDetails;
import io.contexa.contexacommon.entity.UserGroup;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * [최종 수정]
 * 인가 결정을 위한 표준 컨텍스트(AuthorizationContext)를 생성하는 구현체.
 * URL 기반 요청과 메서드 기반 요청을 명확히 구분하여 처리하고,
 * 사용자 정보를 조회하여 컨텍스트를 풍부하게 만듭니다.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DefaultContextHandler implements ContextHandler {

    private final UserRepository userRepository;

    /**
     * URL 기반 보안(Web Security)을 위한 컨텍스트를 생성합니다.
     */
    @Override
    public AuthorizationContext create(Authentication authentication, HttpServletRequest request) {
        // 1. 주체(Subject) 정보 추출
        Users subjectEntity = getSubjectEntity(authentication);

        // 2. 리소스(Resource) 정보 추출
        ResourceDetails resourceDetails = new ResourceDetails("URL", request.getRequestURI());

        // 3. 환경(Environment) 정보 추출
        EnvironmentDetails environmentDetails = new EnvironmentDetails(request.getRemoteAddr(), LocalDateTime.now(), request);

        // 4. 추가 속성(Attributes) 정보 추출
        Map<String, Object> attributes = createAttributesForSubject(subjectEntity);

        return new AuthorizationContext(
                authentication,
                subjectEntity,
                resourceDetails,
                request.getMethod(),
                environmentDetails,
                attributes
        );
    }

    /**
     * 메서드 기반 보안(Method Security)을 위한 컨텍스트를 생성합니다.
     */
    @Override
    public AuthorizationContext create(Authentication authentication, MethodInvocation invocation) {
        // 1. 주체(Subject) 정보 추출
        Users subjectEntity = getSubjectEntity(authentication);

        // 2. 리소스(Resource) 정보 추출
        Method method = invocation.getMethod();
        String params = Arrays.stream(method.getParameterTypes())
                .map(Class::getSimpleName)
                .collect(Collectors.joining(","));
        String resourceIdentifier = String.format("%s.%s(%s)", method.getDeclaringClass().getName(), method.getName(), params);
        ResourceDetails resourceDetails = new ResourceDetails("METHOD", resourceIdentifier);

        // 3. 환경(Environment) 정보 추출 (메서드 호출 시점에는 HttpServletRequest가 없음)
        EnvironmentDetails environmentDetails = new EnvironmentDetails(null, LocalDateTime.now(), null);

        // 4. 추가 속성(Attributes) 정보 추출
        Map<String, Object> attributes = createAttributesForSubject(subjectEntity);

        return new AuthorizationContext(
                authentication,
                subjectEntity,
                resourceDetails,
                "INVOKE", // action (String)
                environmentDetails,
                attributes
        );
    }

    /**
     * Authentication 객체로부터 Users 엔티티를 안전하게 조회합니다.
     */
    private Users getSubjectEntity(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof CustomUserDetails userDetails)) {
            return null;
        }
        return userDetails.getUsers();
    }

    /**
     * Users 엔티티를 기반으로 AI 분석에 사용될 추가 속성(역할, 그룹 등) 맵을 생성합니다.
     */
    private Map<String, Object> createAttributesForSubject(Users subject) {
        if (subject == null) {
            return new HashMap<>();
        }

        // findByIdWithGroupsRolesAndPermissions는 UserRepository에 존재하는 유효한 메서드입니다.
        Users userWithDetails = userRepository.findByIdWithGroupsRolesAndPermissions(subject.getId())
                .orElse(subject);

        Map<String, Object> attributes = new HashMap<>();

        // Users 엔티티에 getRoleNames()는 존재하므로 그대로 사용합니다.
        attributes.put("userRoles", userWithDetails.getRoleNames());

        // [핵심 수정] getGroupNames() 메서드가 없으므로, userGroups를 직접 스트리밍하여 그룹 이름 목록을 생성합니다.
        List<String> groupNames = userWithDetails.getUserGroups().stream()
                .map(UserGroup::getGroup)
                .map(group -> group != null ? group.getName() : null)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
        attributes.put("userGroups", groupNames);

        return attributes;
    }
}