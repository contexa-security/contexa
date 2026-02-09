package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.repository.DocumentRepository;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.AbstractAISecurityExpressionRoot;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
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

@Slf4j
public class CustomMethodSecurityExpressionRoot extends AbstractAISecurityExpressionRoot implements MethodSecurityExpressionOperations {

    private final MethodInvocation invocation;
    private Object filterObject;
    private Object returnObject;
    private Object target;
    private String ownerField;
    private UserRepository userRepository;
    private GroupRepository groupRepository;
    private DocumentRepository documentRepository;
    private ApplicationContext applicationContext;

    public CustomMethodSecurityExpressionRoot(Authentication authentication,
                                              AuthorizationContext authorizationContext,
                                              AuditLogRepository auditLogRepository, MethodInvocation mi) {
        super(authentication, authorizationContext, auditLogRepository);
        this.invocation = mi;
    }

    public void setRepositories(UserRepository userRepository, GroupRepository groupRepository, DocumentRepository documentRepository, ApplicationContext applicationContext) {
        this.userRepository = userRepository;
        this.groupRepository = groupRepository;
        this.documentRepository = documentRepository;
        this.applicationContext = applicationContext;
    }

    @Override
    public boolean hasPermission(Object target, Object permission) {
        if (!super.hasPermission(target, permission)) {
            return false;
        }

        if (StringUtils.hasText(ownerField) && target != null) {
            return checkOwnership(target);
        }
        return true;
    }

    @Override
    public boolean hasPermission(Object targetId, String targetType, Object permission) {

        if (StringUtils.hasText(ownerField) && targetId != null) {
            if (!checkOwnershipById((Serializable) targetId, targetType)) {
                return false;
            }
        }
        return true;
    }

    private boolean checkOwnership(Object target) {
        try {
            String currentUsername = ((UserDto) getAuthentication().getPrincipal()).getUsername();

            Field field = target.getClass().getDeclaredField(ownerField);
            field.setAccessible(true);
            Object ownerValue = field.get(target);

            if (ownerValue == null) {
                return false;
            }

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

    private boolean checkOwnershipById(Serializable targetId, String targetType) {
        try {
            Object entity = findEntityById(targetId, targetType);
            if (entity == null) {
                return false;
            }
            return checkOwnership(entity);

        } catch (Exception e) {
            log.error("ID 기반 소유자 확인 오류: {}", e.getMessage());
            return false;
        }
    }

    private Object findEntityById(Serializable targetId, String targetType) {
        try {
            return switch (targetType.toUpperCase()) {
                case "USER" -> userRepository != null ? userRepository.findById((Long) targetId).orElse(null) : null;
                case "GROUP" -> groupRepository != null ? groupRepository.findById((Long) targetId).orElse(null) : null;
                case "DOCUMENT" ->
                        documentRepository != null ? documentRepository.findById((Long) targetId).orElse(null) : null;
                default -> findEntityByDynamicRepository(targetId, targetType);
            };
        } catch (Exception e) {
            log.warn("엔티티 조회 실패: targetId={}, targetType={}", targetId, targetType, e);
            return null;
        }
    }

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
            return null;
        }
    }

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

    public void setOwnerField(String ownerField) {
        this.ownerField = ownerField;
    }

    @Override
    public Object getThis() {
        return this.target;
    }

    @Override
    protected String getCurrentAction() {
        if (this.invocation != null && this.invocation.getMethod() != null) {
            return this.invocation.getMethod().getName();
        }
        return "UNKNOWN";
    }
}