package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import io.contexa.contexacore.std.operations.AINativeProcessor;
import io.contexa.contexacommon.dto.UserDto;
import io.contexa.contexaiam.repository.DocumentRepository;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.AbstractAISecurityExpressionRoot;
import io.contexa.contexaiam.security.xacml.pip.attribute.AttributeInformationPoint;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.context.ApplicationContext;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Optional;

/**
 * AI 기반 메서드 권한 검증 + 소유자 확인
 */
@Slf4j
public class CustomMethodSecurityExpressionRoot extends AbstractAISecurityExpressionRoot implements MethodSecurityExpressionOperations {

    private static final double SECURITY_THRESHOLD = 0.7;
    private final MethodInvocation invocation;

    private Object filterObject;
    private Object returnObject;
    private Object target;
    
    /**
     * -- SETTER --
     *  🏠 ownerField 설정
     */
    @Setter
    private String ownerField;
    
    // Repository 의존성 (ID 기반 소유자 확인용)
    private UserRepository userRepository;
    private GroupRepository groupRepository;
    private DocumentRepository documentRepository;
    private ApplicationContext applicationContext;

    public CustomMethodSecurityExpressionRoot(Authentication authentication,
                                              AttributeInformationPoint attributePIP,
                                              AuthorizationContext authorizationContext,
                                              AINativeProcessor aINativeProcessor,
                                              AuditLogRepository auditLogRepository, MethodInvocation mi) {
        super(authentication, attributePIP, aINativeProcessor, authorizationContext, auditLogRepository);
        this.invocation = mi;
    }
    
    /**
     * Repository 의존성 설정 (ID 기반 소유자 확인용)
     */
    public void setRepositories(UserRepository userRepository, GroupRepository groupRepository, DocumentRepository documentRepository, ApplicationContext applicationContext) {
        this.userRepository = userRepository;
        this.groupRepository = groupRepository;
        this.documentRepository = documentRepository;
        this.applicationContext = applicationContext;
    }

    @Override
    public boolean hasPermission(Object target, Object permission) {
        // 1. 기본 권한 검증
        if (!super.hasPermission(target, permission)) {
            return false;
        }
        
        // 2. 소유자 확인 (설정된 경우)
        if (StringUtils.hasText(ownerField) && target != null) {
            if (!checkOwnership(target)) {
                return false;
            }
        }
        
        // AI 진단은 SpEL 표현식 #ai.assessContext()에서 수행됨 (중복 제거)
        return true;
    }

    @Override
    public boolean hasPermission(Object targetId, String targetType, Object permission) {
        // 1. 기본 권한 검증
        /*if (!super.hasPermission(targetId, targetType, permission)) {
            return false;
        }*/
        
        // 2. ID 기반 소유자 확인 (설정된 경우)
        if (StringUtils.hasText(ownerField) && targetId != null) {
            if (!checkOwnershipById((Serializable) targetId, targetType)) {
                return false;
            }
        }
        
        // AI 진단은 SpEL 표현식 #ai.assessContext()에서 수행됨 (중복 제거)
        return true;
    }

    /**
     * 🏠 객체 기반 소유자 확인
     */
    private boolean checkOwnership(Object target) {
        try {
            String currentUsername = ((UserDto)getAuthentication().getPrincipal()).getUsername();
            
            // 리플렉션으로 ownerField 값 추출
            Field field = target.getClass().getDeclaredField(ownerField);
            field.setAccessible(true);
            Object ownerValue = field.get(target);
            
            if (ownerValue == null) {
                return false;
            }
            
            // 문자열 비교 (가장 간단한 방식)
            boolean isOwner = currentUsername.equals(ownerValue.toString());
            
            if (!isOwner) {
                log.warn("🚫 객체 기반 소유자 확인 실패 - user: {}, owner: {}", currentUsername, ownerValue);
            }
            
            return isOwner;
            
        } catch (Exception e) {
            log.error("객체 기반 소유자 확인 오류: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * 🏠 ID 기반 소유자 확인
     */
    private boolean checkOwnershipById(Serializable targetId, String targetType) {
        try {
            // 1. 엔티티 조회
            Object entity = findEntityById(targetId, targetType);
            if (entity == null) {
                log.debug("엔티티 조회 실패: targetId={}, targetType={}", targetId, targetType);
                return false;
            }
            
            // 2. 조회된 엔티티로 소유자 확인
            return checkOwnership(entity);
            
        } catch (Exception e) {
            log.error("ID 기반 소유자 확인 오류: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * ID와 타입으로 엔티티 조회
     */
    private Object findEntityById(Serializable targetId, String targetType) {
        try {
            switch (targetType.toUpperCase()) {
                case "USER":
                    return userRepository != null ? userRepository.findById((Long) targetId).orElse(null) : null;
                case "GROUP":
                    return groupRepository != null ? groupRepository.findById((Long) targetId).orElse(null) : null;
                case "DOCUMENT":
                    log.debug("DOCUMENT 타입은 아직 지원되지 않음");
                    return documentRepository != null ? documentRepository.findById((Long) targetId).orElse(null) : null;
                default:
                    // 동적 Repository 조회 시도
                    return findEntityByDynamicRepository(targetId, targetType);
            }
        } catch (Exception e) {
            log.warn("엔티티 조회 실패: targetId={}, targetType={}", targetId, targetType, e);
            return null;
        }
    }
    
    /**
     * 동적 Repository 조회
     */
    private Object findEntityByDynamicRepository(Serializable targetId, String targetType) {
        if (applicationContext == null) {
            return null;
        }
        
        try {
            String repositoryBeanName = targetType.toLowerCase() + "Repository";
            
            if (applicationContext.containsBean(repositoryBeanName)) {
                Object repository = applicationContext.getBean(repositoryBeanName);
                
                Method findByIdMethod = repository.getClass().getMethod("findById", Object.class);
                Object result = findByIdMethod.invoke(repository, targetId);
                
                if (result instanceof Optional) {
                    return ((Optional<?>) result).orElse(null);
                }
                
                return result;
            }
            
            return null;
            
        } catch (Exception e) {
            log.debug("동적 Repository 조회 실패: {}", e.getMessage());
            return null;
        }
    }

    // === Spring Security 인터페이스 구현 ===
    
    @Override
    public void setFilterObject(Object filterObject) {
        this.filterObject = filterObject;
    }

    @Override
    public Object getFilterObject() {
        return this.filterObject;
    }

    @Override
    public void setReturnObject(Object returnObject) {
        this.returnObject = returnObject;
    }

    @Override
    public Object getReturnObject() {
        return this.returnObject;
    }

    void setThis(Object target) {
        this.target = target;
    }

    @Override
    public Object getThis() {
        return this.target;
    }

    // === 부모 클래스 구현 ===

    @Override
    protected String getRemoteIp() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes != null) {
            return attributes.getRequest().getRemoteAddr();
        }
        log.warn("Could not retrieve remote IP address from RequestContextHolder. Returning default value.");
        return "127.0.0.1";
    }

    @Override
    protected String getCurrentActivityDescription() {
        return String.format("Method execution: %s.%s",
                this.invocation.getMethod().getDeclaringClass().getSimpleName(),
                this.invocation.getMethod().getName());
    }

    @Override
    protected ContextExtractionResult extractCurrentContext() {
        return new ContextExtractionResult("127.0.0.1", "method", "call", "INVOKE");
    }

    @Override
    protected String calculateContextHash() {
        return "static";
    }
} 