package io.contexa.contexaiam.security.xacml.pip.context;

import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexacommon.entity.UserGroup;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.core.Authentication;

import java.lang.reflect.Method;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;


@Slf4j
@RequiredArgsConstructor
public class DefaultContextHandler implements ContextHandler {

    private final UserRepository userRepository;

    
    @Override
    public AuthorizationContext create(Authentication authentication, HttpServletRequest request) {
        
        Users subjectEntity = getSubjectEntity(authentication);

        
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
        
        Users subjectEntity = getSubjectEntity(authentication);

        
        Method method = invocation.getMethod();
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

    
    private Users getSubjectEntity(Authentication authentication) {
        if (authentication == null) {
            return null;
        }

        Object principal = authentication.getPrincipal();

        if (principal instanceof Users user) {
            return user;
        }

        if (principal instanceof UnifiedCustomUserDetails userDetails) {
            Long userId = userDetails.getAccount().getId();
            return userRepository.findByIdWithGroupsRolesAndPermissions(userId).orElse(null);
        }

        return null;
    }

    
    private Map<String, Object> createAttributesForSubject(Users subject) {
        if (subject == null) {
            return new HashMap<>();
        }

        
        Users userWithDetails = userRepository.findByIdWithGroupsRolesAndPermissions(subject.getId())
                .orElse(subject);

        Map<String, Object> attributes = new HashMap<>();

        
        attributes.put("userRoles", userWithDetails.getRoleNames());

        
        List<String> groupNames = userWithDetails.getUserGroups().stream()
                .map(UserGroup::getGroup)
                .map(group -> group != null ? group.getName() : null)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
        attributes.put("userGroups", groupNames);

        return attributes;
    }
}