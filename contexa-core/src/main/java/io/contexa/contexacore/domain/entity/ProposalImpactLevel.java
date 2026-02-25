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
