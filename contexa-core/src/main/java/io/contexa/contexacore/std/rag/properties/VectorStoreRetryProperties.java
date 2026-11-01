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
package io.contexa.contexacore.std.rag.properties;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/**
 * Settings of the retry of vector document stores that failed (BR-C4, QF-8): a document whose store failed waits in a
 * bounded queue and is stored again in the background, so that a store outage of minutes does not lose the records
 * the engine learns from.
 */
@ConfigurationProperties(prefix = "contexa.vectorstore.retry")
@Validated
@Data
public class VectorStoreRetryProperties {

    /** Whether failed stores are kept and tried again; off, a failed store is only thrown to the caller. */
    private boolean enabled = true;

    /** The most documents that wait for a retry; when it is full the oldest waiting document is dropped. */
    @Min(1)
    @Max(1_000_000)
    private int queueSize = 2000;

    /** The tries after which a waiting document is given up. */
    @Min(1)
    @Max(1000)
    private int maxAttempts = 20;

    /** The age (from its first failure) after which a waiting document is given up. */
    @NotNull
    private Duration maxAge = Duration.ofHours(1);

    /** The wait before the first retry; it doubles with each retry that fails. */
    @NotNull
    private Duration initialDelay = Duration.ofSeconds(10);

    /** The longest wait between two retries. */
    @NotNull
    private Duration maxDelay = Duration.ofMinutes(5);

    /** The most documents one retry stores; it is halved while retries fail and grows back after they succeed. */
    @Min(1)
    @Max(1000)
    private int batchSize = 20;
}
