package io.contexa.demo.workspace.slot.repository;

import io.contexa.demo.workspace.configuration.WorkspaceSlotDefinition;

import java.util.UUID;

public interface WorkspaceSlotRepository {

    void configure(WorkspaceSlotDefinition slot);

    void registerWorker(String slotId, UUID generation, String arm, UUID instanceId);

    void heartbeat(String slotId, UUID generation, String arm, UUID instanceId);
}
