package io.contexa.contexacore.autonomous.audit;

import org.springframework.context.ApplicationEvent;

/**
 * Spring application event wrapping an AuditRecord for async persistence.
 */
public class AuditRecordEvent extends ApplicationEvent {

    private final AuditRecord auditRecord;

    public AuditRecordEvent(Object source, AuditRecord auditRecord) {
        super(source);
        this.auditRecord = auditRecord;
    }

    public AuditRecord getAuditRecord() {
        return auditRecord;
    }
}
