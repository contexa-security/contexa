package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import com.github.benmanes.caffeine.cache.Cache;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.lang.reflect.Field;
import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class CustomMethodSecurityExpressionRootTest {

    @Mock
    private Authentication authentication;

    @Mock
    private AuthorizationContext authorizationContext;

    @Mock
    private AuditLogRepository auditLogRepository;

    @Mock
    private ZeroTrustActionRepository actionRedisRepository;

    @Mock
    private PermissionEvaluator permissionEvaluator;

    private CustomMethodSecurityExpressionRoot expressionRoot;

    @BeforeEach
    void setUp() throws Exception {
        // Clear static Caffeine cache to prevent cross-test contamination
        Field cacheField = CustomMethodSecurityExpressionRoot.class.getDeclaredField("actionLocalCache");
        cacheField.setAccessible(true);
        ((Cache<?, ?>) cacheField.get(null)).invalidateAll();

        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getName()).thenReturn("testUser");

        expressionRoot = new CustomMethodSecurityExpressionRoot(
                authentication, authorizationContext, auditLogRepository, actionRedisRepository);
        expressionRoot.setPermissionEvaluator(permissionEvaluator);
    }

    @Nested
    @DisplayName("checkOwnership via reflection")
    class CheckOwnershipTest {

        @Test
        @DisplayName("Should allow access when user is owner via field")
        void shouldAllowWhenUserIsOwner() {
            expressionRoot.setOwnerField("createdBy");

            TargetEntity entity = new TargetEntity("testUser");

            when(permissionEvaluator.hasPermission(any(), any(), any())).thenReturn(true);
            Collection<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
            doReturn(authorities).when(authentication).getAuthorities();

            boolean result = expressionRoot.hasPermission(entity, "READ");

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should deny access when user is not owner")
        void shouldDenyWhenUserIsNotOwner() {
            expressionRoot.setOwnerField("createdBy");

            TargetEntity entity = new TargetEntity("otherUser");

            when(permissionEvaluator.hasPermission(any(), any(), any())).thenReturn(true);
            Collection<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
            doReturn(authorities).when(authentication).getAuthorities();

            boolean result = expressionRoot.hasPermission(entity, "READ");

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should allow access for ROLE_ADMIN regardless of ownership")
        void shouldAllowAdminRegardlessOfOwnership() {
            expressionRoot.setOwnerField("createdBy");

            TargetEntity entity = new TargetEntity("otherUser");

            when(permissionEvaluator.hasPermission(any(), any(), any())).thenReturn(true);
            Collection<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
            doReturn(authorities).when(authentication).getAuthorities();

            boolean result = expressionRoot.hasPermission(entity, "READ");

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should deny access when owner field value is null")
        void shouldDenyWhenOwnerFieldValueIsNull() {
            expressionRoot.setOwnerField("createdBy");

            TargetEntity entity = new TargetEntity(null);

            when(permissionEvaluator.hasPermission(any(), any(), any())).thenReturn(true);
            Collection<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
            doReturn(authorities).when(authentication).getAuthorities();

            boolean result = expressionRoot.hasPermission(entity, "READ");

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should skip ownership check when ownerField is not set")
        void shouldSkipOwnershipCheckWhenOwnerFieldNotSet() {
            // ownerField is null by default
            when(permissionEvaluator.hasPermission(any(), any(), any())).thenReturn(true);

            boolean result = expressionRoot.hasPermission(new Object(), "READ");

            assertThat(result).isTrue();
        }
    }

    @Nested
    @DisplayName("hasPermission(targetId, targetType, permission)")
    class HasPermissionByIdTest {

        @Test
        @DisplayName("Should delegate to super and skip ownership when ownerField is not set")
        void shouldDelegateToSuperWhenNoOwnerField() {
            when(permissionEvaluator.hasPermission(any(), any(), anyString(), any())).thenReturn(true);

            boolean result = expressionRoot.hasPermission(1L, "USER", "READ");

            assertThat(result).isTrue();
        }
    }

    @Nested
    @DisplayName("ZeroTrust action via getCurrentAction")
    class ZeroTrustActionTest {

        @Test
        @DisplayName("Should return PENDING_ANALYSIS when user ID is null")
        void shouldReturnPendingWhenUserIdNull() {
            // Create expression root with null authentication name
            when(authentication.getName()).thenReturn(null);
            when(authentication.isAuthenticated()).thenReturn(false);

            CustomMethodSecurityExpressionRoot root = new CustomMethodSecurityExpressionRoot(
                    authentication, authorizationContext, auditLogRepository, actionRedisRepository);

            // getCurrentAction is called internally by isAllowed(), etc.
            // With unauthenticated user, extractUserId returns null -> PENDING_ANALYSIS
            assertThat(root.isAllowed()).isFalse();
        }

        @Test
        @DisplayName("Should return ALLOW action from repository")
        void shouldReturnAllowAction() {
            when(actionRedisRepository.getCurrentAction("testUser")).thenReturn(ZeroTrustAction.ALLOW);

            // isAllowed calls getCurrentAction which calls resolveActionFromRequest (returns null outside web)
            // then calls actionRedisRepository.getCurrentAction
            assertThat(expressionRoot.isAllowed()).isTrue();
            assertThat(expressionRoot.isBlocked()).isFalse();
        }

        @Test
        @DisplayName("Should return BLOCK action from repository")
        void shouldReturnBlockAction() {
            when(actionRedisRepository.getCurrentAction("testUser")).thenReturn(ZeroTrustAction.BLOCK);

            assertThat(expressionRoot.isBlocked()).isTrue();
            assertThat(expressionRoot.isAllowed()).isFalse();
        }
    }

    @Nested
    @DisplayName("MethodSecurityExpressionOperations")
    class ExpressionOperationsTest {

        @Test
        @DisplayName("Should set and get filter object")
        void shouldSetAndGetFilterObject() {
            Object filter = new Object();
            expressionRoot.setFilterObject(filter);

            assertThat(expressionRoot.getFilterObject()).isSameAs(filter);
        }

        @Test
        @DisplayName("Should set and get return object")
        void shouldSetAndGetReturnObject() {
            Object returnObj = new Object();
            expressionRoot.setReturnObject(returnObj);

            assertThat(expressionRoot.getReturnObject()).isSameAs(returnObj);
        }

        @Test
        @DisplayName("Should set and get this target")
        void shouldSetAndGetThis() {
            Object target = new Object();
            expressionRoot.setThis(target);

            assertThat(expressionRoot.getThis()).isSameAs(target);
        }
    }

    // Target entity with owner field for reflection-based ownership checks
    @SuppressWarnings("unused")
    static class TargetEntity {
        private final String createdBy;

        TargetEntity(String createdBy) {
            this.createdBy = createdBy;
        }

        public String getCreatedBy() {
            return createdBy;
        }
    }
}
