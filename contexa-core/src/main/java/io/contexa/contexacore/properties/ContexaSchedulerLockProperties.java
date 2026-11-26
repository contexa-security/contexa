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
 * Configuration surface for the locks of Contexa's own scheduled work.
 * <p>
 * Operators bind these values under {@code contexa.scheduler.lock} in their
 * application configuration. Defaults keep Contexa's locks active so its
 * scheduled work is safe on several JVMs out of the box. Single-instance
 * deployments may keep the default because the lock always succeeds and the
 * overhead is negligible. The locks are Contexa's alone: an
 * {@code @SchedulerLock} method of the application is never locked by
 * Contexa, whatever these values say.
 *
 * @param enabled              Whether Contexa locks its own scheduled work.
 *                             With {@code true} every {@code @SchedulerLock}
 *                             method of Contexa's classes takes its lock in
 *                             Contexa's table {@code ctxa_shedlock} through
 *                             Contexa's lock provider, held under the name
 *                             {@code contexaShedLockProvider} so that the
 *                             application's lookups of a {@code LockProvider}
 *                             by type never find it. Setting this to
 *                             {@code false} leaves Contexa's
 *                             {@code @Scheduled} methods with single-JVM-only
 *                             exclusivity.
 * @param defaultLockAtMostFor Not read: a lock of Contexa's whose annotation
 *                             names no {@code lockAtMostFor} is held at most
 *                             five minutes, whatever this value is.
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
