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
package io.contexa.contexacore.domain.entity;

/**
 * Impact level of a policy evolution proposal on the operational system.
 *
 * <p>Unlike {@link io.contexa.contexacommon.enums.RiskLevel} (CVSS-based security threat
 * assessment for attacks and system compromise), this enum represents the operational
 * impact of a proposed policy change:
 *
 * <ul>
 *   <li>{@code LOW} - Minimal operational impact, auto-approval eligible</li>
 *   <li>{@code MEDIUM} - Moderate impact, single approval typically required</li>
 *   <li>{@code HIGH} - Significant impact, may require multi-approval</li>
 *   <li>{@code CRITICAL} - Severe operational impact, multi-approval mandatory</li>
 * </ul>
 */
public enum ProposalImpactLevel {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}
