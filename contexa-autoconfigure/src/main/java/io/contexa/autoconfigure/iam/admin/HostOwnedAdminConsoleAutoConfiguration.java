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
package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexacommon.operating.ConditionalOnOwnership;
import org.springframework.beans.factory.BeanFactory;
import io.contexa.autoconfigure.core.ContexaOwnBeans;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexacommon.security.authority.AuthorityResolver;
import io.contexa.contexacore.security.UnifiedUserDetailsService;
import io.contexa.contexaiam.admin.web.auth.controller.LoginController;
import io.contexa.contexaidentity.security.zerotrust.HostOwnedUserPathGuard;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.List;

/**
 * The administration console when the application owns sign-in (HOST_OWNED, ownership design S-3). Contexa protects
 * its own console whatever the application's security is: a chain that takes {@code /contexa/admin/**} only (less the
 * user's own paths there, see {@link #consoleRequests()}) and signs
 * Contexa's administrators in with Contexa's user store (an authentication manager of this chain only; no global bean
 * is added). Everything it keeps in the HTTP session has keys of its own, so an administrator and an application user
 * in one browser do not overwrite each other, and its sign-out does not end the application's session.
 * <p>
 * It runs after Spring Boot's security configuration on purpose: Spring Boot decides whether the application gets its
 * default chain (when it declares none) before this chain exists, so the application keeps the security it had.
 */
@AutoConfiguration(afterName = {
        "org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration",
        "org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration"})
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(SecurityFilterChain.class)
@ConditionalOnOwnership(SecurityOwnershipMode.HOST_OWNED)
public class HostOwnedAdminConsoleAutoConfiguration {

    /** The bean name of the console's chain; Contexa's diagnostics leave it out of the application's chains. */
    public static final String ADMIN_CHAIN = "contexaAdminConsoleSecurityFilterChain";

    /** The console's sign-out; the application's {@code /logout} stays the application's. */
    public static final String LOGOUT_URL = "/contexa/admin/logout";

    static final String CONTEXT_KEY = "CONTEXA_ADMIN_SECURITY_CONTEXT";
    static final String CSRF_KEY = "CONTEXA_ADMIN_CSRF_TOKEN";
    static final String SAVED_REQUEST_KEY = "CONTEXA_ADMIN_SAVED_REQUEST";

    @Bean(ADMIN_CHAIN)
    @Order(Ordered.HIGHEST_PRECEDENCE + 10)
    @ConditionalOnMissingBean(name = ADMIN_CHAIN)
    public SecurityFilterChain contexaAdminConsoleSecurityFilterChain(HttpSecurity http,
                                                                      UserRepository userRepository,
                                                                      AuthorityResolver contexaAuthorityResolver,
                                                                      BeanFactory beanFactory,
                                                                      ObjectProvider<LoginPolicyHandler> loginPolicy)
            throws Exception {
        DaoAuthenticationProvider provider =
                new DaoAuthenticationProvider(new UnifiedUserDetailsService(userRepository, contexaAuthorityResolver));
        provider.setPasswordEncoder(ContexaOwnBeans.passwordEncoder(beanFactory));
        // The console's sign-ins count against Contexa's accounts (failed attempts, lock, address throttle); the
        // application's own never do (the policy's event listener runs only when Contexa owns sign-in).
        ProviderManager manager = new ProviderManager(provider);
        manager.setAuthenticationEventPublisher(new ConsoleLoginPolicyEvents(loginPolicy));

        HttpSessionSecurityContextRepository contextRepository = new HttpSessionSecurityContextRepository();
        contextRepository.setSpringSecurityContextKey(CONTEXT_KEY);
        HttpSessionCsrfTokenRepository csrfRepository = new HttpSessionCsrfTokenRepository();
        csrfRepository.setSessionAttributeName(CSRF_KEY);
        HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
        requestCache.setSessionAttrName(SAVED_REQUEST_KEY);
        // Only a page is returned to after sign-in, never a call of the console's API.
        requestCache.setRequestMatcher(new NegatedRequestMatcher(
                PathPatternRequestMatcher.withDefaults().matcher("/contexa/admin/api/**")));

        String login = LoginController.HOST_OWNED_LOGIN_PROCESSING_URL;
        return http
                .securityMatcher(consoleRequests())
                .authenticationManager(manager)
                .securityContext(context -> context.securityContextRepository(contextRepository))
                .csrf(csrf -> csrf.csrfTokenRepository(csrfRepository))
                .requestCache(cache -> cache.requestCache(requestCache))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(login).permitAll()
                        .anyRequest().hasRole("ADMIN"))
                .formLogin(form -> form
                        .loginPage(login)
                        .loginProcessingUrl(login)
                        .defaultSuccessUrl("/contexa/admin", false)
                        .failureUrl(login + "?error")
                        .permitAll())
                .logout(logout -> logout
                        .logoutRequestMatcher(PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, LOGOUT_URL))
                        .logoutSuccessUrl(login)
                        .invalidateHttpSession(false))
                .exceptionHandling(exceptions -> exceptions
                        .defaultAuthenticationEntryPointFor(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                                PathPatternRequestMatcher.withDefaults().matcher("/contexa/admin/api/**"))
                        .defaultAuthenticationEntryPointFor(new LoginUrlAuthenticationEntryPoint(login),
                                PathPatternRequestMatcher.withDefaults().matcher("/contexa/admin/**")))
                .build();
    }

    /**
     * The console's requests: /contexa/admin and below, except the user's own paths there (the release of a block, the
     * pending analysis), which stay behind the application's chain for its signed-in user ({@link HostOwnedUserPathGuard}).
     */
    static RequestMatcher consoleRequests() {
        PathPatternRequestMatcher.Builder paths = PathPatternRequestMatcher.withDefaults();
        List<RequestMatcher> userPaths = HostOwnedUserPathGuard.ADMIN_SELF_SERVICE_PREFIXES.stream()
                .<RequestMatcher>map(prefix -> paths.matcher(prefix + "/**"))
                .toList();
        return new AndRequestMatcher(
                new OrRequestMatcher(paths.matcher("/contexa/admin"), paths.matcher("/contexa/admin/**")),
                new NegatedRequestMatcher(new OrRequestMatcher(userPaths)));
    }

    @Bean(name = "contexaHostOwnedConsoleModelAdvice")
    @ConditionalOnMissingBean
    public HostOwnedConsoleModelAdvice hostOwnedConsoleModelAdvice() {
        return new HostOwnedConsoleModelAdvice();
    }
}
