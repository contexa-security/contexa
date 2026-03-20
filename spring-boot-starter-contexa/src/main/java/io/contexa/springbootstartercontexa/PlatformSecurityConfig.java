package io.contexa.springbootstartercontexa;

import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpCustomizer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;

@Slf4j
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class PlatformSecurityConfig {

    private final CustomDynamicAuthorizationManager customDynamicAuthorizationManager;
    private final AISessionSecurityContextRepository aiSessionSecurityContextRepository;

    @Bean
    public PlatformConfig platformDslConfig(IdentityDslRegistry<HttpSecurity> registry) throws Exception {

        SafeHttpCustomizer<HttpSecurity> globalHttpCustomizer = http -> {
            http
//                    .logout(logout -> logout.logoutUrl("/admin/logout").logoutSuccessUrl("/admin/mfa/login"))
                    .csrf(AbstractHttpConfigurer::disable)
                    .authorizeHttpRequests(authReq -> authReq
                            .requestMatchers("/css/**", "/js/**", "/images/**", "/favicon.ico").permitAll()
                            .anyRequest().access(customDynamicAuthorizationManager)
                    )
                    .securityContext(sc -> sc.securityContextRepository(aiSessionSecurityContextRepository))
            ;
        };
        return registry
                .global(globalHttpCustomizer)
/*
                .form(form -> form.order(20)
                        .loginPage("/admin/login")
                        .defaultSuccessUrl("/admin")
                        .rawHttp(http-> http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)))
                )
                .oauth2(Customizer.withDefaults())
*/
//                .rest(rest -> rest.order(10)
//                        .defaultSuccessUrl("/admin")).session(Customizer.withDefaults())
//                .ott(ott -> ott.order(30)).session(Customizer.withDefaults())
//                .passkey(passkey -> passkey.order(40)).session(Customizer.withDefaults())

                /*.form(form -> form.order(50)).oauth2(Customizer.withDefaults())
                .rest(rest -> rest.order(60)).oauth2(Customizer.withDefaults())
                .ott(ott -> ott.order(70)).oauth2(Customizer.withDefaults())
                .passkey(passkey -> passkey.order(80)).oauth2(Customizer.withDefaults())*/
                .mfa(mfa -> mfa.urlPrefix("/admin").requiredFactors(1)
                                .primaryAuthentication(auth -> auth.formLogin(form -> form
                                        .defaultSuccessUrl("/admin")
                                        .rawHttp(http -> http.securityMatcher("/admin/**"))))
                                .passkey(Customizer.withDefaults())
                                .ott(Customizer.withDefaults())
                                .passkey(Customizer.withDefaults())
                                .ott(Customizer.withDefaults())
                        .order(60)
                ).session(Customizer.withDefaults())
                .mfa(mfa -> mfa.requiredFactors(1)
                        .primaryAuthentication(auth -> auth.formLogin(form -> form
                                .defaultSuccessUrl("/test/zero-trust-index")))
//                        .primaryAuthentication(auth -> auth.restLogin(Customizer.withDefaults()))
                        .passkey(Customizer.withDefaults())
                        .ott(Customizer.withDefaults())
                        /*.mfaPage(page ->
                                page
                                        .ottPages("/custom/mfa/ott/request-code-ui", "/custom/mfa/challenge/ott")
                                        .passkeyChallengePages("/custom/challenge/passkey"))*/
                        .order(70)
                ).session(Customizer.withDefaults())

                .build();
    }
}