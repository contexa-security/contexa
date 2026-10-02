package io.contexa.demo.workspace.slot.bootstrap;

import io.contexa.demo.configuration.properties.LabProperties;
import io.contexa.demo.workspace.configuration.WorkspaceAccessProperties;
import io.contexa.demo.workspace.slot.repository.WorkspaceSlotRepository;
import io.contexa.demo.workspace.slot.service.WorkspaceGenerationFence;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.annotation.Profile;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.scheduling.annotation.Scheduled;

import java.util.UUID;

@Component
@Profile({"baseline", "contexa"})
public class WorkspaceWorkerInitializer {

    private final WorkspaceAccessProperties properties;
    private final WorkspaceSlotRepository slots;
    private final LabProperties lab;
    private final WorkspaceGenerationFence generationFence;
    private final UUID instanceId = UUID.randomUUID();
    private volatile boolean ready;

    public WorkspaceWorkerInitializer(WorkspaceAccessProperties properties, WorkspaceSlotRepository slots,
            LabProperties lab, WorkspaceGenerationFence generationFence) {
        this.properties = properties;
        this.slots = slots;
        this.lab = lab;
        this.generationFence = generationFence;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void register() {
        if (!properties.enabled()) {
            return;
        }
        generationFence.requireReady();
        slots.registerWorker(properties.workerSlotId(), properties.workerGeneration(), lab.role(), instanceId);
        ready = true;
    }

    @Scheduled(fixedDelay = 5000)
    public void heartbeat() {
        if (properties.enabled() && ready) {
            slots.heartbeat(properties.workerSlotId(), properties.workerGeneration(), lab.role(), instanceId);
        }
    }
}
