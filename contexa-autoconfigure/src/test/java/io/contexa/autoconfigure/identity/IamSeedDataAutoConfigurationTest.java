package io.contexa.autoconfigure.identity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

class IamSeedDataAutoConfigurationTest {

    @Test
    @DisplayName("IAM seed data should use a Contexa-owned classpath location")
    void iamSeedDataUsesContexaOwnedClasspathLocation() {
        assertThat(IamSeedDataAutoConfiguration.IAM_SEED_DATA_LOCATION)
                .isEqualTo("contexa/iam/data.sql");
        assertThat(new ClassPathResource(IamSeedDataAutoConfiguration.IAM_SEED_DATA_LOCATION).exists())
                .isTrue();
    }

    @Test
    @DisplayName("IAM SQL resources should not be exposed at Spring Boot SQL init default locations")
    void iamSqlResourcesAreNotExposedAtSpringBootSqlInitDefaultLocations() {
        assertThat(new ClassPathResource("data.sql").exists()).isFalse();
        assertThat(new ClassPathResource("schema.sql").exists()).isFalse();
        assertThat(new ClassPathResource("data-menu.sql").exists()).isFalse();
    }
}
