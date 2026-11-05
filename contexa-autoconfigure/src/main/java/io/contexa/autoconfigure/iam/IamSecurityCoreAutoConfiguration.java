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
package io.contexa.autoconfigure.iam;

import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.security.AISecurityContextSupport;
import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import io.contexa.contexacore.security.AIOAuth2SecurityContextRepository;
import io.contexa.contexacore.security.SessionAccountRefresher;
import io.contexa.contexacore.security.async.AsyncSecurityContextProvider;
import io.contexa.contexacore.security.session.InMemorySessionIdResolver;
import io.contexa.contexacore.security.session.RedisSessionIdResolver;
import io.contexa.contexacore.security.session.SessionIdResolver;
import io.contexa.contexacore.security.zerotrust.InMemoryZeroTrustSecurityService;
import io.contexa.contexacore.security.zerotrust.RedisZeroTrustSecurityService;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import io.contexa.contexacore.properties.SecuritySessionProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.security.core.LoginAttemptIpUpserter;
import io.contexa.contexaiam.security.core.LoginPolicyService;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexacommon.repository.LoginAttemptIpRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.lang.Nullable;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Clock;

@AutoConfiguration
@AutoConfigureAfter(name = {
        "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration",
        "io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration"
})
@EnableConfigurationProperties({ SecurityZeroTrustProperties.class, SecuritySessionProperties.class })
@Import(IamSecurityCoreContexaOwnedConfiguration.class)
public class IamSecurityCoreAutoConfiguration {

    @Bean(name = "contexaLoginAttemptIpUpserter")
    @ConditionalOnMissingBean
    public LoginAttemptIpUpserter loginAttemptIpUpserter(LoginAttemptIpRepository loginAttemptIpRepository) {
        return new LoginAttemptIpUpserter(loginAttemptIpRepository);
    }

    @Bean(name = "contexaLoginPolicyHandler")
    @ConditionalOnMissingBean
    public LoginPolicyHandler loginPolicyHandler(UserRepository userRepository,
                                                  LoginAttemptIpRepository loginAttemptIpRepository,
                                                  PasswordPolicyService contexaPasswordPolicyService,
                                                  LoginAttemptIpUpserter contexaLoginAttemptIpUpserter,
                                                  ObjectProvider<SecurityContextDataStore> securityContextDataStoreProvider) {
        return new LoginPolicyService(userRepository, loginAttemptIpRepository,
                contexaPasswordPolicyService, contexaLoginAttemptIpUpserter, securityContextDataStoreProvider);
    }

    @Bean(name = "contexaAiSecurityContextSupport")
    @ConditionalOnMissingBean
    public AISecurityContextSupport aiSecurityContextSupport(
            SecurityZeroTrustProperties securityZeroTrustProperties,
            @Nullable ZeroTrustSecurityService contexaZeroTrustSecurityService,
            @Nullable SessionIdResolver sessionIdResolver) {
        return new AISecurityContextSupport(securityZeroTrustProperties, contexaZeroTrustSecurityService, sessionIdResolver);
    }

    @Bean(name = "contexaAiSessionSecurityContextRepository", defaultCandidate = false)
    @ConditionalOnMissingBean
    public AISessionSecurityContextRepository aiSessionSecurityContextRepository(
            AISecurityContextSupport contexaAiSecurityContextSupport,
            @Nullable SecurityContextDataStore securityContextDataStore,
            @Nullable AsyncSecurityContextProvider contexaAsyncSecurityContextProvider,
            @Qualifier("contexaUnifiedUserDetailsService") ObjectProvider<UserDetailsService> contexaAccounts) {
        AISessionSecurityContextRepository repository = new AISessionSecurityContextRepository(
                contexaAiSecurityContextSupport,
                securityContextDataStore,
                contexaAsyncSecurityContextProvider);
        UserDetailsService accounts = contexaAccounts.getIfAvailable();
        if (securityContextDataStore != null && accounts != null) {
            repository.setAccountRefresher(new SessionAccountRefresher(securityContextDataStore, accounts));
        }
        return repository;
    }

    @Bean(name = "contexaAiOAuth2SecurityContextRepository")
    @ConditionalOnMissingBean
    public AIOAuth2SecurityContextRepository aiOAuth2SecurityContextRepository(
            AISecurityContextSupport contexaAiSecurityContextSupport) {
        return new AIOAuth2SecurityContextRepository(contexaAiSecurityContextSupport);
    }

    @Configuration
    @ConditionalOnClass(name = "org.springframework.data.redis.core.RedisTemplate")
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    @ConditionalOnBean(type = "org.springframework.data.redis.core.RedisTemplate")
    static class DistributedSecurityConfig {

        @Bean(name = "contexaZeroTrustSecurityService")
        @ConditionalOnMissingBean(ZeroTrustSecurityService.class)
        public RedisZeroTrustSecurityService zeroTrustSecurityService(
                @Qualifier("contexaGeneralRedisTemplate") RedisTemplate<String, Object> redisTemplate,
                ThreatScoreUtil threatScoreUtil,
                SecurityZeroTrustProperties securityZeroTrustProperties,
                ZeroTrustActionRepository actionRedisRepository) {
            return new RedisZeroTrustSecurityService(redisTemplate,
                    threatScoreUtil, securityZeroTrustProperties, actionRedisRepository);
        }

        @Bean(name = "contexaRedisSessionIdResolver")
        @ConditionalOnMissingBean(SessionIdResolver.class)
        public RedisSessionIdResolver redisSessionIdResolver(
                @Qualifier("contexaGeneralRedisTemplate") RedisTemplate<String, Object> redisTemplate,
                SecuritySessionProperties securitySessionProperties) {
            return new RedisSessionIdResolver(redisTemplate, securitySessionProperties);
        }
    }

    @Bean(name = "contexaInMemorySessionIdResolver")
    @ConditionalOnMissingBean(SessionIdResolver.class)
    public SessionIdResolver inMemorySessionIdResolver(SecuritySessionProperties securitySessionProperties) {
        return new InMemorySessionIdResolver(securitySessionProperties);
    }

    /**
     * Z-16 (2-a, 2-c): as the Redis service, invalidations last {@code contexa.security.zerotrust.cache.ttl-hours}
     * and a forced logout also reaches the ids of the context store's list of the user's sessions.
     */
    @Bean(name = "contexaInMemoryZeroTrustSecurityService")
    @ConditionalOnMissingBean(ZeroTrustSecurityService.class)
    public InMemoryZeroTrustSecurityService inMemoryZeroTrustSecurityService(
            ThreatScoreUtil threatScoreUtil,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ZeroTrustActionRepository actionRepository,
            @Nullable BlockingSignalBroadcaster blockingSignalBroadcaster,
            @Nullable SecurityContextDataStore securityContextDataStore) {
        return new InMemoryZeroTrustSecurityService(threatScoreUtil, securityZeroTrustProperties, actionRepository,
                blockingSignalBroadcaster, securityContextDataStore, Clock.systemUTC());
    }
}

