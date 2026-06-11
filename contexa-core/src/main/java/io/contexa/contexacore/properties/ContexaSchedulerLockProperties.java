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
package io.contexa.contexacore.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

/**
 * Configuration surface for the Contexa ShedLock auto-configuration.
 * <p>
 * Operators bind these values under {@code contexa.scheduler.lock} in their
 * application configuration. Defaults keep ShedLock active so multi-JVM
 * deployments are safe out of the box. Single-instance deployments may keep
 * the default because the lock always succeeds and the overhead is
 * negligible.
 *
 * @param enabled              Whether the ShedLock auto-configuration registers
 *                             a {@code LockProvider} bean. Setting this to
 *                             {@code false} disables every
 *                             {@code @SchedulerLock} and each
 *                             {@code @Scheduled} method reverts to
 *                             single-JVM-only exclusivity.
 * @param defaultLockAtMostFor Fallback upper bound applied when a specific
 *                             scheduler omits {@code lockAtMostFor}. Prevents
 *                             stuck locks from surviving indefinitely after a
 *                             JVM crash.
 * @param useDatabaseTime      When true the {@code JdbcTemplateLockProvider}
 *                             uses {@code now()} from the database engine so
 *                             every instance sees the same clock. When false
 *                             the provider falls back to the JVM clock, which
 *                             can simplify local H2 tests whose database
 *                             timezone is not aligned with the JVM.
 */
@ConfigurationProperties(prefix = "contexa.scheduler.lock")
public record ContexaSchedulerLockProperties(
        @DefaultValue("true") boolean enabled,
        @DefaultValue("5m") Duration defaultLockAtMostFor,
        @DefaultValue("true") boolean useDatabaseTime) {
}
