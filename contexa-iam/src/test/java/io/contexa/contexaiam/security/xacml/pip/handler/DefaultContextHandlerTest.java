package io.contexa.contexaiam.security.xacml.pip.handler;

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.UserGroup;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexaiam.security.xacml.pip.context.DefaultContextHandler;
import jakarta.servlet.http.HttpServletRequest;
import org.aopalliance.intercept.MethodInvocation;
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
import org.springframework.security.core.GrantedAuthority;

import java.lang.reflect.Method;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DefaultContextHandlerTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private DefaultContextHandler contextHandler;

    @Nested
    @DisplayName("HTTP request context creation")
    class HttpRequestContext {

        @Test
        @DisplayName("should create context with subject, resource, action, and environment from HTTP request")
        void shouldCreateContextFromHttpRequest() {
            // given
            Users user = createTestUser(1L, "testuser");
            Authentication auth = mockAuthenticationWithUser(user);
            HttpServletRequest request = mock(HttpServletRequest.class);

            when(request.getRequestURI()).thenReturn("/api/users");
            when(request.getMethod()).thenReturn("GET");
            when(request.getRemoteAddr()).thenReturn("192.168.1.1");
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L))
                    .thenReturn(Optional.of(user));

            // when
            AuthorizationContext context = contextHandler.create(auth, request);

            // then
            assertThat(context).isNotNull();
            assertThat(context.subject()).isEqualTo(auth);
            assertThat(context.subjectEntity()).isEqualTo(user);
            assertThat(context.resource().type()).isEqualTo("URL");
            assertThat(context.resource().identifier()).isEqualTo("/api/users");
            assertThat(context.action()).isEqualTo("GET");
            assertThat(context.environment()).isNotNull();
            assertThat(context.environment().remoteIp()).isEqualTo("192.168.1.1");
            assertThat(context.environment().timestamp()).isNotNull();
        }

        @Test
        @DisplayName("should handle null authentication gracefully")
        void shouldHandleNullAuthentication() {
            // given
            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getRequestURI()).thenReturn("/api/test");
            when(request.getMethod()).thenReturn("POST");
            when(request.getRemoteAddr()).thenReturn("10.0.0.1");

            // when
            AuthorizationContext context = contextHandler.create(null, request);

            // then
            assertThat(context).isNotNull();
            assertThat(context.subjectEntity()).isNull();
            assertThat(context.attributes()).isEmpty();
        }
    }

    @Nested
    @DisplayName("Method call context creation")
    class MethodCallContext {

        @Test
        @DisplayName("should create context from MethodInvocation with correct resource identifier")
        void shouldCreateContextFromMethodInvocation() throws Exception {
            // given
            Users user = createTestUser(2L, "admin");
            Authentication auth = mockAuthenticationWithUser(user);
            MethodInvocation invocation = mock(MethodInvocation.class);
            Method method = String.class.getMethod("substring", int.class, int.class);

            when(invocation.getMethod()).thenReturn(method);
            when(userRepository.findByIdWithGroupsRolesAndPermissions(2L))
                    .thenReturn(Optional.of(user));

            // when
            AuthorizationContext context = contextHandler.create(auth, invocation);

            // then
            assertThat(context).isNotNull();
            assertThat(context.resource().type()).isEqualTo("METHOD");
            assertThat(context.resource().identifier())
                    .contains("java.lang.String")
                    .contains("substring")
                    .contains("int,int");
            assertThat(context.action()).isEqualTo("INVOKE");
            assertThat(context.environment().remoteIp()).isNull();
            assertThat(context.environment().request()).isNull();
        }

        @Test
        @DisplayName("should create context with no-arg method correctly")
        void shouldHandleNoArgMethod() throws Exception {
            // given
            Users user = createTestUser(3L, "user1");
            Authentication auth = mockAuthenticationWithUser(user);
            MethodInvocation invocation = mock(MethodInvocation.class);
            Method method = String.class.getMethod("length");

            when(invocation.getMethod()).thenReturn(method);
            when(userRepository.findByIdWithGroupsRolesAndPermissions(3L))
                    .thenReturn(Optional.of(user));

            // when
            AuthorizationContext context = contextHandler.create(auth, invocation);

            // then
            assertThat(context.resource().identifier())
                    .contains("java.lang.String")
                    .contains("length()")
                    .doesNotContain(",");
        }
    }

    @Nested
    @DisplayName("Subject entity extraction from Authentication")
    class SubjectExtraction {

        @Test
        @DisplayName("should extract Users entity directly when principal is Users")
        void shouldExtractUsersDirectly() {
            // given
            Users user = createTestUser(10L, "directuser");
            Authentication auth = mock(Authentication.class);
            when(auth.getPrincipal()).thenReturn(user);

            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getRequestURI()).thenReturn("/test");
            when(request.getMethod()).thenReturn("GET");
            when(request.getRemoteAddr()).thenReturn("127.0.0.1");
            when(userRepository.findByIdWithGroupsRolesAndPermissions(10L))
                    .thenReturn(Optional.of(user));

            // when
            AuthorizationContext context = contextHandler.create(auth, request);

            // then
            assertThat(context.subjectEntity()).isEqualTo(user);
        }

        @Test
        @DisplayName("should convert UnifiedCustomUserDetails to Users via repository lookup")
        void shouldConvertUnifiedCustomUserDetails() {
            // given
            UserDto userDto = UserDto.builder().id(20L).username("detailsuser").build();
            UnifiedCustomUserDetails details = new UnifiedCustomUserDetails(userDto, new HashSet<>());
            Users expectedUser = createTestUser(20L, "detailsuser");

            Authentication auth = mock(Authentication.class);
            when(auth.getPrincipal()).thenReturn(details);
            when(userRepository.findByIdWithGroupsRolesAndPermissions(20L))
                    .thenReturn(Optional.of(expectedUser));

            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getRequestURI()).thenReturn("/test");
            when(request.getMethod()).thenReturn("GET");
            when(request.getRemoteAddr()).thenReturn("127.0.0.1");

            // when
            AuthorizationContext context = contextHandler.create(auth, request);

            // then
            assertThat(context.subjectEntity()).isEqualTo(expectedUser);
            // Called twice: once in getSubjectEntity, once in createAttributesForSubject
            verify(userRepository, atLeast(1)).findByIdWithGroupsRolesAndPermissions(20L);
        }

        @Test
        @DisplayName("should return null subject when principal type is unknown")
        void shouldReturnNullForUnknownPrincipalType() {
            // given
            Authentication auth = mock(Authentication.class);
            when(auth.getPrincipal()).thenReturn("stringPrincipal");

            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getRequestURI()).thenReturn("/test");
            when(request.getMethod()).thenReturn("GET");
            when(request.getRemoteAddr()).thenReturn("127.0.0.1");

            // when
            AuthorizationContext context = contextHandler.create(auth, request);

            // then
            assertThat(context.subjectEntity()).isNull();
            assertThat(context.attributes()).isEmpty();
        }
    }

    @Nested
    @DisplayName("Roles and groups attribute extraction")
    class RolesAndGroupsExtraction {

        @Test
        @DisplayName("should populate userRoles and userGroups attributes from Users entity")
        void shouldExtractRolesAndGroups() {
            // given
            Users user = createTestUser(5L, "groupuser");
            Group group1 = mock(Group.class);
            when(group1.getName()).thenReturn("developers");
            Group group2 = mock(Group.class);
            when(group2.getName()).thenReturn("admins");

            UserGroup ug1 = mock(UserGroup.class);
            when(ug1.getGroup()).thenReturn(group1);
            UserGroup ug2 = mock(UserGroup.class);
            when(ug2.getGroup()).thenReturn(group2);
            // user is a mock, so setUserGroups() is a no-op; must stub getUserGroups() instead
            when(user.getUserGroups()).thenReturn(Set.of(ug1, ug2));

            Authentication auth = mockAuthenticationWithUser(user);
            when(userRepository.findByIdWithGroupsRolesAndPermissions(5L))
                    .thenReturn(Optional.of(user));

            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getRequestURI()).thenReturn("/api/data");
            when(request.getMethod()).thenReturn("GET");
            when(request.getRemoteAddr()).thenReturn("10.0.0.1");

            // when
            AuthorizationContext context = contextHandler.create(auth, request);

            // then
            assertThat(context.attributes()).containsKey("userGroups");
            @SuppressWarnings("unchecked")
            List<String> groups = (List<String>) context.attributes().get("userGroups");
            assertThat(groups).containsExactlyInAnyOrder("developers", "admins");
            assertThat(context.attributes()).containsKey("userRoles");
        }

        @Test
        @DisplayName("should handle user with null groups gracefully")
        void shouldHandleNullGroups() {
            // given
            Users user = createTestUser(6L, "nogroups");
            user.setUserGroups(new HashSet<>());

            Authentication auth = mockAuthenticationWithUser(user);
            when(userRepository.findByIdWithGroupsRolesAndPermissions(6L))
                    .thenReturn(Optional.of(user));

            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getRequestURI()).thenReturn("/test");
            when(request.getMethod()).thenReturn("GET");
            when(request.getRemoteAddr()).thenReturn("127.0.0.1");

            // when
            AuthorizationContext context = contextHandler.create(auth, request);

            // then
            @SuppressWarnings("unchecked")
            List<String> groups = (List<String>) context.attributes().get("userGroups");
            assertThat(groups).isEmpty();
        }
    }

    // -- helper methods --

    private Users createTestUser(Long id, String username) {
        Users user = mock(Users.class);
        when(user.getId()).thenReturn(id);
        when(user.getUsername()).thenReturn(username);
        when(user.getUserGroups()).thenReturn(new HashSet<>());
        when(user.getRoleNames()).thenReturn(Collections.emptyList());
        return user;
    }

    private Authentication mockAuthenticationWithUser(Users user) {
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn(user);
        return auth;
    }
}
