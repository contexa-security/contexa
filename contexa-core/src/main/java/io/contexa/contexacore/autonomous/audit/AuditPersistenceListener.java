package io.contexa.contexacore.autonomous.audit;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;

/**
 * Async event listener that persists AuditRecord to database.
 * Decouples audit recording from business logic execution.
 */
@Slf4j
public class AuditPersistenceListener {

    private final CentralAuditFacade centralAuditFacade;

    public AuditPersistenceListener(CentralAuditFacade centralAuditFacade) {
        this.centralAuditFacade = centralAuditFacade;
    }

    @Async
    @EventListener
    public void onAuditRecordEvent(AuditRecordEvent event) {
        try {
            centralAuditFacade.persist(event.getAuditRecord());
        } catch (Exception e) {
            log.error("Failed to persist audit record asynchronously: category={}, principal={}",
                    event.getAuditRecord().getEventCategory(),
                    event.getAuditRecord().getPrincipalName(), e);
        }
    }
}
