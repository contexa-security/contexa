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
package io.contexa.contexaiam.admin.promptquality.version;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.TaskScheduler;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ScheduledFuture;

/**
 * What a node does with the versions once it has started (plan 3.3, 3.8 8, 6-3 7): it registers the product documents
 * of its build for the platform scope (the first installation's v1.0, an upgrade's next numbers), retires the registry
 * rows of earlier bundles, and, with a document folder, reads the folder then and every minute after. Every node does
 * it; the unique origin of a version keeps a document registered once. A failure is logged and the node goes on: the
 * engine runs the product document until the versions can be read.
 */
public class PromptVersionStartup {

    private static final Logger log = LoggerFactory.getLogger(PromptVersionStartup.class);

    /** How often the folder is read after the start (plan 3.8, 8). */
    public static final Duration FOLDER_INTERVAL = Duration.ofMinutes(1);

    private final PromptVersionService versions;
    private final PromptVersionFolderScanner folder;

    /**
     * @param versions the versions of the database
     * @param folder   the document folder of the node; null without the setting {@code contexa.prompt.versions.directory}
     */
    public PromptVersionStartup(PromptVersionService versions, PromptVersionFolderScanner folder) {
        this.versions = Objects.requireNonNull(versions, "versions");
        this.folder = folder;
    }

    /**
     * Registers the products and retires the earlier bundles, then reads the folder once and has the scheduler read it
     * every minute; returns the scheduled reading, or null without a folder or a scheduler.
     */
    public ScheduledFuture<?> start(TaskScheduler scheduler) {
        try {
            List<PromptVersionService.Saved> made = versions.registerProducts(PromptVersionService.PLATFORM_SCOPE);
            if (!made.isEmpty()) {
                log.info("[PromptVersion] product versions registered: {}", made.stream()
                        .map(PromptVersionService.Saved::name).toList());
            }
            versions.retireEarlierBundles(PromptVersionService.PLATFORM_SCOPE);
        }
        catch (RuntimeException failure) {
            log.error("[PromptVersion] the product versions could not be registered at start; decisions run the product"
                    + " document until they are", failure);
        }
        if (folder == null) {
            return null;
        }
        readFolder();
        if (scheduler == null) {
            log.warn("[PromptVersionFolder] no scheduler: the document folder was read once at start and is not read"
                    + " again");
            return null;
        }
        return scheduler.scheduleWithFixedDelay(this::readFolder, Instant.now().plus(FOLDER_INTERVAL),
                FOLDER_INTERVAL);
    }

    private void readFolder() {
        try {
            folder.scan();
        }
        catch (RuntimeException failure) {
            log.error("[PromptVersionFolder] the document folder could not be read", failure);
        }
    }
}
