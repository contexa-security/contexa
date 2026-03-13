package io.contexa.contexaiam.security.xacml.prp;

import com.fasterxml.jackson.core.type.TypeReference;
import io.contexa.contexacommon.cache.ContexaCacheService;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.PolicyRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.List;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DatabasePolicyRetrievalPointTest {

    @Mock
    private PolicyRepository policyRepository;

    @Mock
    private ContexaCacheService cacheService;

    @InjectMocks
    private DatabasePolicyRetrievalPoint retrievalPoint;

    @Nested
    @DisplayName("URL policy retrieval")
    class UrlPolicyRetrieval {

        @Test
        @DisplayName("should retrieve URL policies through cache service")
        void shouldRetrieveUrlPoliciesThroughCache() {
            // given
            Policy policy1 = Policy.builder().id(1L).name("url-policy-1").build();
            Policy policy2 = Policy.builder().id(2L).name("url-policy-2").build();
            List<Policy> expectedPolicies = List.of(policy1, policy2);

            when(cacheService.get(eq("policies:url:all"), any(Supplier.class), any(TypeReference.class), eq("policies")))
                    .thenReturn(expectedPolicies);

            // when
            List<Policy> result = retrievalPoint.findUrlPolicies();

            // then
            assertThat(result).hasSize(2);
            assertThat(result).containsExactlyElementsOf(expectedPolicies);
            verify(cacheService).get(eq("policies:url:all"), any(Supplier.class), any(TypeReference.class), eq("policies"));
        }

        @Test
        @DisplayName("should use correct cache key for URL policies")
        void shouldUseCorrectCacheKeyForUrlPolicies() {
            // given
            when(cacheService.get(anyString(), any(Supplier.class), any(TypeReference.class), anyString()))
                    .thenReturn(List.of());

            // when
            retrievalPoint.findUrlPolicies();

            // then
            ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
            verify(cacheService).get(keyCaptor.capture(), any(Supplier.class), any(TypeReference.class), eq("policies"));
            assertThat(keyCaptor.getValue()).isEqualTo("policies:url:all");
        }

        @Test
        @DisplayName("should load from repository when cache misses (via supplier)")
        void shouldLoadFromRepositoryOnCacheMiss() {
            // given
            Policy policy = Policy.builder().id(1L).name("loaded-policy").build();
            List<Policy> dbPolicies = List.of(policy);
            when(policyRepository.findByTargetTypeWithDetails("URL")).thenReturn(dbPolicies);

            // Simulate cache miss by invoking the supplier
            when(cacheService.get(eq("policies:url:all"), any(Supplier.class), any(TypeReference.class), eq("policies")))
                    .thenAnswer(invocation -> {
                        Supplier<List<Policy>> supplier = invocation.getArgument(1);
                        return supplier.get();
                    });

            // when
            List<Policy> result = retrievalPoint.findUrlPolicies();

            // then
            assertThat(result).hasSize(1);
            assertThat(result.get(0).getName()).isEqualTo("loaded-policy");
            verify(policyRepository).findByTargetTypeWithDetails("URL");
        }
    }

    @Nested
    @DisplayName("Method policy retrieval")
    class MethodPolicyRetrieval {

        @Test
        @DisplayName("should retrieve method policies with correct cache key")
        void shouldRetrieveMethodPoliciesWithCorrectKey() {
            // given
            String methodId = "com.example.Service.doWork(String)";
            Policy policy = Policy.builder().id(3L).name("method-policy").build();

            when(cacheService.get(eq("policies:method:" + methodId), any(Supplier.class), any(TypeReference.class), eq("policies")))
                    .thenReturn(List.of(policy));

            // when
            List<Policy> result = retrievalPoint.findMethodPolicies(methodId);

            // then
            assertThat(result).hasSize(1);
            verify(cacheService).get(
                    eq("policies:method:com.example.Service.doWork(String)"),
                    any(Supplier.class),
                    any(TypeReference.class),
                    eq("policies")
            );
        }

        @Test
        @DisplayName("should load method policies from repository on cache miss")
        void shouldLoadMethodPoliciesFromRepository() {
            // given
            String methodId = "com.example.Service.process(int)";
            Policy policy = Policy.builder().id(4L).name("repo-method-policy").build();
            when(policyRepository.findByMethodIdentifier(methodId)).thenReturn(List.of(policy));

            when(cacheService.get(anyString(), any(Supplier.class), any(TypeReference.class), anyString()))
                    .thenAnswer(invocation -> {
                        Supplier<List<Policy>> supplier = invocation.getArgument(1);
                        return supplier.get();
                    });

            // when
            List<Policy> result = retrievalPoint.findMethodPolicies(methodId);

            // then
            assertThat(result).hasSize(1);
            assertThat(result.get(0).getName()).isEqualTo("repo-method-policy");
            verify(policyRepository).findByMethodIdentifier(methodId);
        }

        @Test
        @DisplayName("should use different cache keys for different method identifiers")
        void shouldUseDifferentCacheKeysForDifferentMethods() {
            // given
            when(cacheService.get(anyString(), any(Supplier.class), any(TypeReference.class), anyString()))
                    .thenReturn(List.of());

            // when
            retrievalPoint.findMethodPolicies("method.A()");
            retrievalPoint.findMethodPolicies("method.B()");

            // then
            verify(cacheService).get(eq("policies:method:method.A()"), any(Supplier.class), any(TypeReference.class), eq("policies"));
            verify(cacheService).get(eq("policies:method:method.B()"), any(Supplier.class), any(TypeReference.class), eq("policies"));
        }
    }

    @Nested
    @DisplayName("Cache invalidation")
    class CacheInvalidation {

        @Test
        @DisplayName("should invalidate URL policies cache with correct key")
        void shouldInvalidateUrlPoliciesCache() {
            // when
            retrievalPoint.clearUrlPoliciesCache();

            // then
            verify(cacheService).invalidate("policies:url:all");
        }

        @Test
        @DisplayName("should invalidate method policies cache with wildcard pattern")
        void shouldInvalidateMethodPoliciesCacheWithWildcard() {
            // when
            retrievalPoint.clearMethodPoliciesCache();

            // then
            verify(cacheService).invalidate("policies:method:*");
        }

        @Test
        @DisplayName("should allow re-fetching URL policies after cache invalidation")
        void shouldAllowRefetchAfterUrlCacheInvalidation() {
            // given
            Policy fresh = Policy.builder().id(10L).name("fresh-policy").build();
            when(cacheService.get(eq("policies:url:all"), any(Supplier.class), any(TypeReference.class), eq("policies")))
                    .thenReturn(List.of(fresh));

            // when
            retrievalPoint.clearUrlPoliciesCache();
            List<Policy> result = retrievalPoint.findUrlPolicies();

            // then
            verify(cacheService).invalidate("policies:url:all");
            assertThat(result).hasSize(1);
            assertThat(result.get(0).getName()).isEqualTo("fresh-policy");
        }

        @Test
        @DisplayName("should allow re-fetching method policies after cache invalidation")
        void shouldAllowRefetchAfterMethodCacheInvalidation() {
            // given
            Policy fresh = Policy.builder().id(11L).name("fresh-method-policy").build();
            when(cacheService.get(anyString(), any(Supplier.class), any(TypeReference.class), anyString()))
                    .thenReturn(List.of(fresh));

            // when
            retrievalPoint.clearMethodPoliciesCache();
            List<Policy> result = retrievalPoint.findMethodPolicies("some.method()");

            // then
            verify(cacheService).invalidate("policies:method:*");
            assertThat(result).hasSize(1);
        }
    }
}
