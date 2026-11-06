/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.security.xacml.pip.context;

import com.fasterxml.jackson.core.type.TypeReference;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncResult;
import io.contexa.contexacommon.cache.ContexaCacheService;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexacommon.entity.UserGroup;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.store.StoreFailures;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.aop.support.AopUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.security.core.Authentication;

import java.lang.reflect.Method;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class DefaultContextHandler implements ContextHandler {

    private final UserRepository userRepository;
    private final ContexaCacheService cacheService;

    private static final TypeReference<Users> USERS_TYPE = new TypeReference<>() {};

    @Override
    public AuthorizationContext create(Authentication authentication, HttpServletRequest request) {
        
        Users subjectEntity = getSubjectEntity(authentication, request);

        ResourceDetails resourceDetails = new ResourceDetails("URL", request.getRequestURI());

        EnvironmentDetails environmentDetails = new EnvironmentDetails(request.getRemoteAddr(), LocalDateTime.now(), request);

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

    @Override
    public AuthorizationContext create(Authentication authentication, MethodInvocation invocation) {
        
        Users subjectEntity = getSubjectEntity(authentication, currentRequest());

        Method method = resolveSpecificMethod(invocation);
        String params = Arrays.stream(method.getParameterTypes())
                .map(Class::getSimpleName)
                .collect(Collectors.joining(","));
        String resourceIdentifier = String.format("%s.%s(%s)", method.getDeclaringClass().getName(), method.getName(), params);
        ResourceDetails resourceDetails = new ResourceDetails("METHOD", resourceIdentifier);

        EnvironmentDetails environmentDetails = new EnvironmentDetails(null, LocalDateTime.now(), null);

        Map<String, Object> attributes = createAttributesForSubject(subjectEntity);

        return new AuthorizationContext(
                authentication,
                subjectEntity,
                resourceDetails,
                "INVOKE", 
                environmentDetails,
                attributes
        );
    }

    private Method resolveSpecificMethod(MethodInvocation invocation) {
        Method method = invocation.getMethod();
        Object target = invocation.getThis();
        if (target == null) {
            return method;
        }

        Class<?> targetClass = AopProxyUtils.ultimateTargetClass(target);
        if (targetClass == null) {
            return method;
        }

        return AopUtils.getMostSpecificMethod(method, targetClass);
    }

    /**
     * The policies decide on the authentication when the subject's record cannot be read: a store that does not answer
     * must not cost a policy that can still be evaluated, a DENY among them (Q-7).
     */
    private Users getSubjectEntity(Authentication authentication, HttpServletRequest request) {
        try {
            return readSubjectEntity(authentication, request);
        } catch (RuntimeException unreadable) {
            if (!StoreFailures.isStoreFailure(unreadable)) {
                throw unreadable;
            }
            return null;
        }
    }

    private Users readSubjectEntity(Authentication authentication, HttpServletRequest request) {
        Users bridgeSubject = getBridgeSubjectEntity(request);
        if (bridgeSubject != null) {
            return bridgeSubject;
        }
        if (authentication == null) {
            return null;
        }

        Object principal = authentication.getPrincipal();

        if (principal instanceof Users user) {
            return user;
        }

        if (principal instanceof UnifiedCustomUserDetails userDetails) {
            Long userId = userDetails.getAccount().getId();
            if (userId != null) {
                return cacheService.get(SubjectCache.byId(userId),
                        () -> userRepository.findByIdWithGroupsRolesAndPermissions(userId).orElse(null),
                        USERS_TYPE, SubjectCache.DOMAIN);
            }
            String username = userDetails.getUsername();
            if (username != null) {
                return cacheService.get(SubjectCache.byName(username),
                        () -> userRepository.findByUsernameWithGroupsRolesAndPermissions(username).orElse(null),
                        USERS_TYPE, SubjectCache.DOMAIN);
            }
            return null;
        }

        return null;
    }

    private Users getBridgeSubjectEntity(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        Object value = request.getAttribute(BridgeRequestAttributes.USER_SYNC_RESULT);
        if (!(value instanceof BridgeUserMirrorSyncResult syncResult)
                || syncResult.internalUserId() == null) {
            return null;
        }
        Long userId = syncResult.internalUserId();
        return cacheService.get(SubjectCache.byId(userId),
                () -> userRepository.findByIdWithGroupsRolesAndPermissions(userId).orElse(null),
                USERS_TYPE, SubjectCache.DOMAIN);
    }

    private HttpServletRequest currentRequest() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
            return attributes.getRequest();
        }
        return null;
    }

    private Map<String, Object> createAttributesForSubject(Users subject) {
        if (subject == null) {
            return new HashMap<>();
        }

        Map<String, Object> attributes = new HashMap<>();

        attributes.put("userRoles", subject.getRoleNames());

        List<String> groupNames = subject.getUserGroups().stream()
                .map(UserGroup::getGroup)
                .map(group -> group != null ? group.getName() : null)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
        attributes.put("userGroups", groupNames);

        return attributes;
    }
}
