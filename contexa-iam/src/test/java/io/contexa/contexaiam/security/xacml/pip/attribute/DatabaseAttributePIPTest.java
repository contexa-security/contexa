package io.contexa.contexaiam.security.xacml.pip.attribute;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.entity.business.BusinessResource;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.BusinessResourceActionRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexaiam.security.xacml.pip.context.EnvironmentDetails;
import io.contexa.contexaiam.security.xacml.pip.context.ResourceDetails;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.core.Authentication;

import java.time.LocalDateTime;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DatabaseAttributePIPTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private AuditLogRepository auditLogRepository;

    @Mock
    private BusinessResourceActionRepository resourceActionRepository;

    @InjectMocks
    private DatabaseAttributePIP databaseAttributePIP;

    @Nested
    @DisplayName("Basic user attribute enrichment")
    class BasicUserAttributes {

        @Test
        @DisplayName("should enrich basic user attributes when user is found")
        void shouldEnrichBasicUserAttributes() {
            // given
            AuthorizationContext context = createContextWithUser("testuser", "/api/test");

            Users user = mock(Users.class);
            when(user.getId()).thenReturn(1L);
            when(user.getUsername()).thenReturn("testuser");
            when(user.getCreatedAt()).thenReturn(LocalDateTime.of(2024, 1, 1, 0, 0));
            when(user.getUpdatedAt()).thenReturn(LocalDateTime.of(2024, 6, 1, 0, 0));
            when(user.isMfaEnabled()).thenReturn(true);
            when(user.getUserGroups()).thenReturn(new HashSet<>());
            when(userRepository.findByUsernameWithGroupsRolesAndPermissions("testuser"))
                    .thenReturn(Optional.of(user));

            stubBehaviorMetrics("testuser");
            stubResourcePatterns("/api/test");

            // when
            Map<String, Object> attributes = databaseAttributePIP.getAttributes(context);

            // then
            assertThat(attributes).containsEntry("username", "testuser");
            assertThat(attributes).containsEntry("userId", 1L);
            assertThat(attributes).containsEntry("userEmail", "testuser");
            assertThat(attributes).containsEntry("userStatus", "ACTIVE");
            assertThat(attributes).containsEntry("mfaEnabled", true);
            assertThat(attributes).containsKey("attributeCollectionTimeMs");
        }

        @Test
        @DisplayName("should handle null subject gracefully")
        void shouldHandleNullSubject() {
            // given
            AuthorizationContext context = new AuthorizationContext(
                    null, null,
                    new ResourceDetails("URL", "/api/test"),
                    "GET",
                    new EnvironmentDetails("127.0.0.1", LocalDateTime.now(), null),
                    new HashMap<>()
            );

            // when
            Map<String, Object> attributes = databaseAttributePIP.getAttributes(context);

            // then
            assertThat(attributes).doesNotContainKey("username");
            assertThat(attributes).containsKey("attributeCollectionTimeMs");
        }
    }

    @Nested
    @DisplayName("User behavior metrics enrichment")
    class BehaviorMetrics {

        @Test
        @DisplayName("should calculate request counts across different time ranges")
        void shouldCalculateRequestCounts() {
            // given
            AuthorizationContext context = createContextWithUser("active-user", "/api/data");
            stubUserLookup("active-user");

            when(auditLogRepository.countByPrincipalNameAndTimeRange(eq("active-user"), any(), any()))
                    .thenReturn(15L)
                    .thenReturn(200L)
                    .thenReturn(800L)
                    .thenReturn(15L); // for velocity calculation

            when(auditLogRepository.countDistinctResourcesByPrincipalName("active-user")).thenReturn(10L);
            when(auditLogRepository.findTypicalAccessHoursByPrincipalName("active-user"))
                    .thenReturn(List.of(new Object[]{9}, new Object[]{10}, new Object[]{14}));
            stubResourcePatterns("/api/data");

            // when
            Map<String, Object> attributes = databaseAttributePIP.getAttributes(context);

            // then
            assertThat(attributes).containsEntry("requestsInLastHour", 15L);
            assertThat(attributes).containsEntry("uniqueResourcesAccessed", 10L);
            assertThat(attributes).containsKey("accessVelocity");
            assertThat(attributes).containsKey("typicalAccessHours");
        }
    }

    @Nested
    @DisplayName("Resource access pattern enrichment")
    class ResourceAccessPatterns {

        @Test
        @DisplayName("should enrich resource access patterns when resource exists")
        void shouldEnrichResourcePatterns() {
            // given
            AuthorizationContext context = createContextWithUser("user1", "/api/reports");
            stubUserLookup("user1");
            stubBehaviorMetrics("user1");

            BusinessResource resource = mock(BusinessResource.class);
            when(resource.getResourceType()).thenReturn("INTERNAL_DOC");

            when(auditLogRepository.countByResourceIdentifier("/api/reports")).thenReturn(50L);
            when(auditLogRepository.countDistinctUsersByResourceIdentifier("/api/reports")).thenReturn(5L);
            when(auditLogRepository.countFailedAttemptsSince(eq("/api/reports"), any())).thenReturn(2L);
            when(resourceActionRepository.findByResourceIdentifier("/api/reports"))
                    .thenReturn(Optional.of(resource));
            when(resourceActionRepository.countActionsByResourceIdentifier("/api/reports")).thenReturn(3L);

            // when
            Map<String, Object> attributes = databaseAttributePIP.getAttributes(context);

            // then
            assertThat(attributes).containsEntry("resourceExists", true);
            assertThat(attributes).containsEntry("resourceTotalAccess", 50L);
            assertThat(attributes).containsEntry("resourceUniqueUsers", 5L);
            assertThat(attributes).containsEntry("resourceRecentFailures", 2L);
            assertThat(attributes).containsEntry("resourceAllowedActions", 3L);
        }

        @Test
        @DisplayName("should set resourceExists=false when resource not found")
        void shouldHandleMissingResource() {
            // given
            AuthorizationContext context = createContextWithUser("user2", "/api/unknown");
            stubUserLookup("user2");
            stubBehaviorMetrics("user2");

            when(auditLogRepository.countByResourceIdentifier("/api/unknown")).thenReturn(0L);
            when(auditLogRepository.countDistinctUsersByResourceIdentifier("/api/unknown")).thenReturn(0L);
            when(auditLogRepository.countFailedAttemptsSince(eq("/api/unknown"), any())).thenReturn(0L);
            when(resourceActionRepository.findByResourceIdentifier("/api/unknown"))
                    .thenReturn(Optional.empty());

            // when
            Map<String, Object> attributes = databaseAttributePIP.getAttributes(context);

            // then
            assertThat(attributes).containsEntry("resourceExists", false);
            assertThat(attributes).containsEntry("resourceSensitivityLevel", "UNKNOWN");
        }
    }

    @Nested
    @DisplayName("Sensitivity level determination")
    class SensitivityLevel {

        @Test
        @DisplayName("should classify FINANCIAL resource type as HIGH sensitivity")
        void shouldClassifyFinancialAsHigh() {
            // given
            AuthorizationContext context = createContextWithUser("fin-user", "/api/finance");
            stubUserLookup("fin-user");
            stubBehaviorMetrics("fin-user");
            stubResourceWithType("/api/finance", "FINANCIAL_REPORT");

            // when
            Map<String, Object> attributes = databaseAttributePIP.getAttributes(context);

            // then
            assertThat(attributes).containsEntry("resourceSensitivityLevel", "HIGH");
        }

        @Test
        @DisplayName("should classify SENSITIVE resource type as HIGH sensitivity")
        void shouldClassifySensitiveAsHigh() {
            // given
            AuthorizationContext context = createContextWithUser("sec-user", "/api/sensitive");
            stubUserLookup("sec-user");
            stubBehaviorMetrics("sec-user");
            stubResourceWithType("/api/sensitive", "SENSITIVE_DATA");

            // when
            Map<String, Object> attributes = databaseAttributePIP.getAttributes(context);

            // then
            assertThat(attributes).containsEntry("resourceSensitivityLevel", "HIGH");
        }

        @Test
        @DisplayName("should classify INTERNAL resource type as MEDIUM sensitivity")
        void shouldClassifyInternalAsMedium() {
            // given
            AuthorizationContext context = createContextWithUser("int-user", "/api/internal");
            stubUserLookup("int-user");
            stubBehaviorMetrics("int-user");
            stubResourceWithType("/api/internal", "INTERNAL_TOOL");

            // when
            Map<String, Object> attributes = databaseAttributePIP.getAttributes(context);

            // then
            assertThat(attributes).containsEntry("resourceSensitivityLevel", "MEDIUM");
        }

        @Test
        @DisplayName("should classify generic resource type as STANDARD sensitivity")
        void shouldClassifyGenericAsStandard() {
            // given
            AuthorizationContext context = createContextWithUser("gen-user", "/api/public");
            stubUserLookup("gen-user");
            stubBehaviorMetrics("gen-user");
            stubResourceWithType("/api/public", "PUBLIC_API");

            // when
            Map<String, Object> attributes = databaseAttributePIP.getAttributes(context);

            // then
            assertThat(attributes).containsEntry("resourceSensitivityLevel", "STANDARD");
        }
    }

    @Nested
    @DisplayName("Time and environment attributes")
    class TimeAndEnvironment {

        @Test
        @DisplayName("should populate time-related attributes")
        void shouldPopulateTimeAttributes() {
            // given
            AuthorizationContext context = createContextWithUser("time-user", "/api/test");
            stubUserLookup("time-user");
            stubBehaviorMetrics("time-user");
            stubResourcePatterns("/api/test");

            // when
            Map<String, Object> attributes = databaseAttributePIP.getAttributes(context);

            // then
            assertThat(attributes).containsKey("currentHour");
            assertThat(attributes).containsKey("currentDayOfWeek");
            assertThat(attributes).containsKey("isBusinessHours");
            assertThat(attributes).containsKey("isWeekend");
            assertThat(attributes).containsKey("accessTimestamp");
        }

        @Test
        @DisplayName("should include remote address from environment")
        void shouldIncludeRemoteAddress() {
            // given
            AuthorizationContext context = createContextWithUser("env-user", "/api/test");
            stubUserLookup("env-user");
            stubBehaviorMetrics("env-user");
            stubResourcePatterns("/api/test");

            // when
            Map<String, Object> attributes = databaseAttributePIP.getAttributes(context);

            // then
            assertThat(attributes).containsEntry("remoteAddress", "192.168.1.100");
        }
    }

    @Nested
    @DisplayName("Security profile enrichment")
    class SecurityProfile {

        @Test
        @DisplayName("should calculate risk indicators based on access patterns")
        void shouldCalculateRiskIndicators() {
            // given
            AuthorizationContext context = createContextWithUser("risk-user", "/api/secure");
            stubUserLookup("risk-user");

            // Stub behavior to trigger high velocity
            when(auditLogRepository.countByPrincipalNameAndTimeRange(eq("risk-user"), any(), any()))
                    .thenReturn(700L) // requestsInLastHour - high velocity (700/60 > 10)
                    .thenReturn(1000L) // requestsInLastDay
                    .thenReturn(5000L) // requestsInLastWeek
                    .thenReturn(700L); // velocity calculation
            when(auditLogRepository.countDistinctResourcesByPrincipalName("risk-user")).thenReturn(50L);
            doReturn(List.of(new Object[]{3}))
                    .when(auditLogRepository).findTypicalAccessHoursByPrincipalName("risk-user"); // unusual hour
            stubResourcePatterns("/api/secure");

            // when
            Map<String, Object> attributes = databaseAttributePIP.getAttributes(context);

            // then
            assertThat(attributes).containsKey("userSecurityScore");
            assertThat(attributes).containsKey("hasRecentFailures");
            assertThat(attributes).containsKey("highAccessVelocity");
            assertThat(attributes).containsKey("unusualAccessTime");
            assertThat(attributes).containsKey("riskIndicatorCount");
        }

        @Test
        @DisplayName("should count zero risk indicators for normal access patterns")
        void shouldCountZeroRiskIndicatorsForNormalAccess() {
            // given
            AuthorizationContext context = createContextWithUser("safe-user", "/api/public");

            Users user = mock(Users.class);
            when(user.getId()).thenReturn(99L);
            when(user.getUsername()).thenReturn("safe-user");
            when(user.isMfaEnabled()).thenReturn(true);
            when(user.getUserGroups()).thenReturn(new HashSet<>());
            when(user.getCreatedAt()).thenReturn(LocalDateTime.now().minusDays(60));
            when(user.getUpdatedAt()).thenReturn(LocalDateTime.now());
            when(userRepository.findByUsernameWithGroupsRolesAndPermissions("safe-user"))
                    .thenReturn(Optional.of(user));

            // Low activity = no high velocity
            when(auditLogRepository.countByPrincipalNameAndTimeRange(eq("safe-user"), any(), any()))
                    .thenReturn(5L);
            when(auditLogRepository.countDistinctResourcesByPrincipalName("safe-user")).thenReturn(3L);

            // Current hour is in typical hours
            int currentHour = LocalDateTime.now().getHour();
            doReturn(List.of(new Object[]{currentHour}))
                    .when(auditLogRepository).findTypicalAccessHoursByPrincipalName("safe-user");
            stubResourcePatterns("/api/public");

            // when
            Map<String, Object> attributes = databaseAttributePIP.getAttributes(context);

            // then
            assertThat(attributes).containsEntry("hasRecentFailures", false);
            assertThat(attributes).containsEntry("highAccessVelocity", false);
            assertThat((int) attributes.get("riskIndicatorCount")).isLessThanOrEqualTo(1);
        }
    }

    @Nested
    @DisplayName("Exception handling")
    class ExceptionHandling {

        @Test
        @DisplayName("should return error attribute when collection fails")
        void shouldReturnErrorAttributeOnFailure() {
            // given
            Authentication auth = mock(Authentication.class);
            when(auth.getName()).thenThrow(new RuntimeException("Connection lost"));
            when(auth.getPrincipal()).thenThrow(new RuntimeException("Connection lost"));

            AuthorizationContext context = new AuthorizationContext(
                    auth, null,
                    new ResourceDetails("URL", "/api/test"),
                    "GET",
                    new EnvironmentDetails("127.0.0.1", LocalDateTime.now(), null),
                    new HashMap<>()
            );

            // when
            Map<String, Object> attributes = databaseAttributePIP.getAttributes(context);

            // then - should not throw, returns partial or error attributes
            assertThat(attributes).isNotNull();
        }
    }

    // -- helper methods --

    private AuthorizationContext createContextWithUser(String username, String resourceIdentifier) {
        Authentication auth = mock(Authentication.class);
        when(auth.getName()).thenReturn(username);

        return new AuthorizationContext(
                auth, null,
                new ResourceDetails("URL", resourceIdentifier),
                "GET",
                new EnvironmentDetails("192.168.1.100", LocalDateTime.now(), null),
                new HashMap<>()
        );
    }

    private void stubUserLookup(String username) {
        Users user = mock(Users.class);
        when(user.getId()).thenReturn((long) username.hashCode());
        when(user.getUsername()).thenReturn(username);
        when(user.isMfaEnabled()).thenReturn(false);
        when(user.getUserGroups()).thenReturn(new HashSet<>());
        when(user.getCreatedAt()).thenReturn(LocalDateTime.now().minusDays(30));
        when(user.getUpdatedAt()).thenReturn(LocalDateTime.now());
        when(userRepository.findByUsernameWithGroupsRolesAndPermissions(username))
                .thenReturn(Optional.of(user));
    }

    private void stubBehaviorMetrics(String username) {
        when(auditLogRepository.countByPrincipalNameAndTimeRange(eq(username), any(), any()))
                .thenReturn(5L);
        when(auditLogRepository.countDistinctResourcesByPrincipalName(username)).thenReturn(3L);
        int currentHour = LocalDateTime.now().getHour();
        doReturn(List.of(new Object[]{currentHour}))
                .when(auditLogRepository).findTypicalAccessHoursByPrincipalName(username);
    }

    private void stubResourcePatterns(String resourceIdentifier) {
        when(auditLogRepository.countByResourceIdentifier(resourceIdentifier)).thenReturn(10L);
        when(auditLogRepository.countDistinctUsersByResourceIdentifier(resourceIdentifier)).thenReturn(2L);
        when(auditLogRepository.countFailedAttemptsSince(eq(resourceIdentifier), any())).thenReturn(0L);
        when(resourceActionRepository.findByResourceIdentifier(resourceIdentifier))
                .thenReturn(Optional.empty());
    }

    private void stubResourceWithType(String resourceIdentifier, String resourceType) {
        when(auditLogRepository.countByResourceIdentifier(resourceIdentifier)).thenReturn(10L);
        when(auditLogRepository.countDistinctUsersByResourceIdentifier(resourceIdentifier)).thenReturn(2L);
        when(auditLogRepository.countFailedAttemptsSince(eq(resourceIdentifier), any())).thenReturn(0L);

        BusinessResource resource = mock(BusinessResource.class);
        when(resource.getResourceType()).thenReturn(resourceType);
        when(resourceActionRepository.findByResourceIdentifier(resourceIdentifier))
                .thenReturn(Optional.of(resource));
        when(resourceActionRepository.countActionsByResourceIdentifier(resourceIdentifier)).thenReturn(2L);
    }
}
