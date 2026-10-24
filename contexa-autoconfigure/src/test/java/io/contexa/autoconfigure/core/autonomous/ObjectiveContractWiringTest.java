package io.contexa.autoconfigure.core.autonomous;

import io.contexa.contexacore.autonomous.execution.ObjectiveContractSource;
import io.contexa.contexacore.autonomous.execution.ObjectiveResourceCompatibilityCatalog;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;

import java.lang.reflect.Method;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A2-1: the objective contracts delegations are compared with are Contexa's own, the ones the application writes in
 * {@code contexa.security.zerotrust.agent.objective-contracts} and the ones its {@link ObjectiveContractSource} beans
 * declare; a later contract of a family takes the earlier one's place, and the application may replace the catalog.
 */
class ObjectiveContractWiringTest {

    @Test
    void theCatalogHoldsTheConfiguredAndDeclaredContracts() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        SecurityZeroTrustProperties.ObjectiveContract reporting = new SecurityZeroTrustProperties.ObjectiveContract();
        reporting.setOperations(List.of("READ", "EXPORT"));
        reporting.setResourceFamilies(List.of("PROJECT_DOCUMENTS"));
        reporting.setMaxExportItems(500);
        properties.getAgent().getObjectiveContracts().put("REPORTING", reporting);
        SecurityZeroTrustProperties.ObjectiveContract review = new SecurityZeroTrustProperties.ObjectiveContract();
        review.setOperations(List.of("READ"));
        properties.getAgent().getObjectiveContracts().put("REVIEW", review);
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        beans.registerSingleton("reviewContracts", (ObjectiveContractSource) () -> List.of(
                new ObjectiveResourceCompatibilityCatalog.ObjectiveContractDefinition("REVIEW", List.of("READ", "QUERY"),
                        List.of("PROJECT_DOCUMENTS"), true, false, null)));

        ObjectiveResourceCompatibilityCatalog catalog = new CoreAutonomousAutoConfiguration()
                .objectiveResourceCompatibilityCatalog(properties, beans.getBeanProvider(ObjectiveContractSource.class));

        assertThat(catalog.resolve("REPORTING").maxExportItems()).isEqualTo(500);
        assertThat(catalog.resolve("REPORTING").allowedOperations()).containsExactlyInAnyOrder("READ", "EXPORT");
        assertThat(catalog.resolve("REVIEW").allowedOperations()).containsExactlyInAnyOrder("READ", "QUERY");
        assertThat(catalog.resolve("REVIEW").readOnlyObjective()).isTrue();
        assertThat(catalog.hasObjectiveContract("READ_ONLY_INCIDENT_SUMMARY")).isTrue();
    }

    @Test
    void withoutDeclaredContractsTheCatalogIsContexasOwnAndCanBeReplaced() throws Exception {
        ObjectiveResourceCompatibilityCatalog catalog = new CoreAutonomousAutoConfiguration()
                .objectiveResourceCompatibilityCatalog(new SecurityZeroTrustProperties(),
                        new DefaultListableBeanFactory().getBeanProvider(ObjectiveContractSource.class));
        Method method = CoreAutonomousAutoConfiguration.class.getDeclaredMethod("objectiveResourceCompatibilityCatalog",
                SecurityZeroTrustProperties.class, ObjectProvider.class);

        assertThat(catalog.hasObjectiveContract("REPORTING")).isFalse();
        assertThat(catalog.hasObjectiveContract("INCIDENT_RESPONSE")).isTrue();
        assertThat(method.getAnnotation(ConditionalOnMissingBean.class)).isNotNull();
    }
}
