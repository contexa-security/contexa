package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class SecurityDecisionForwardingOutboxRepositoryTest {

    @Autowired
    private SecurityDecisionForwardingOutboxRepository repository;

    @Test
    void claimForDispatchAtomicallyMovesOnlyReadyRowsToDispatching() {
        SecurityDecisionForwardingOutboxRecord saved = repository.saveAndFlush(SecurityDecisionForwardingOutboxRecord.builder()
                .correlationId("corr-claim-001")
                .tenantExternalRef("tenant-acme")
                .payloadJson("{\"correlationId\":\"corr-claim-001\"}")
                .status(SecurityDecisionForwardingOutboxRecord.STATUS_PENDING)
                .attemptCount(0)
                .createdAt(LocalDateTime.now().minusSeconds(10))
                .updatedAt(LocalDateTime.now().minusSeconds(10))
                .build());

        List<Long> ids = repository.findDispatchableIds(
                List.of(SecurityDecisionForwardingOutboxRecord.STATUS_PENDING, SecurityDecisionForwardingOutboxRecord.STATUS_FAILED),
                LocalDateTime.now(),
                PageRequest.of(0, 10));
        assertThat(ids).contains(saved.getId());

        int claimed = repository.claimForDispatch(
                saved.getId(),
                List.of(SecurityDecisionForwardingOutboxRecord.STATUS_PENDING, SecurityDecisionForwardingOutboxRecord.STATUS_FAILED),
                SecurityDecisionForwardingOutboxRecord.STATUS_DISPATCHING,
                LocalDateTime.now());

        assertThat(claimed).isEqualTo(1);
        SecurityDecisionForwardingOutboxRecord claimedRecord = repository.findById(saved.getId()).orElseThrow();
        assertThat(claimedRecord.getStatus()).isEqualTo(SecurityDecisionForwardingOutboxRecord.STATUS_DISPATCHING);
        assertThat(claimedRecord.getAttemptCount()).isEqualTo(1);

        int duplicateClaim = repository.claimForDispatch(
                saved.getId(),
                List.of(SecurityDecisionForwardingOutboxRecord.STATUS_PENDING, SecurityDecisionForwardingOutboxRecord.STATUS_FAILED),
                SecurityDecisionForwardingOutboxRecord.STATUS_DISPATCHING,
                LocalDateTime.now());

        assertThat(duplicateClaim).isZero();
    }

    @EnableJpaRepositories(
            basePackageClasses = SecurityDecisionForwardingOutboxRepository.class,
            includeFilters = @ComponentScan.Filter(
                    type = FilterType.ASSIGNABLE_TYPE,
                    classes = SecurityDecisionForwardingOutboxRepository.class))
    @EntityScan(basePackageClasses = SecurityDecisionForwardingOutboxRecord.class)
    @SpringBootConfiguration
    static class RepositoryTestConfig {
    }
}
