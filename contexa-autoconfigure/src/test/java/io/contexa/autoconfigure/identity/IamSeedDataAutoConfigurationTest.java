package io.contexa.autoconfigure.identity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;

class IamSeedDataAutoConfigurationTest {

    @Test
    @DisplayName("IAM SQL resources should not be exposed at Spring Boot SQL init default locations")
    void iamSqlResourcesAreNotExposedAtSpringBootSqlInitDefaultLocations() {
        assertThat(new ClassPathResource("data.sql").exists()).isFalse();
        assertThat(new ClassPathResource("schema.sql").exists()).isFalse();
        assertThat(new ClassPathResource("data-menu.sql").exists()).isFalse();
    }

    @Test
    @DisplayName("IAM seed data should run before demo persona JPA provisioning")
    void iamSeedDataRunsBeforePersonaProvisioning() throws NoSuchMethodException {
        Method runner = IamSeedDataAutoConfiguration.class.getDeclaredMethod("iamSeedDataRunner", javax.sql.DataSource.class);

        assertThat(runner.getAnnotation(Order.class))
                .as("IAM seed must run before demo persona runners so users_id_seq is synced first")
                .isNotNull()
                .extracting(Order::value)
                .isEqualTo(10);
    }
}
