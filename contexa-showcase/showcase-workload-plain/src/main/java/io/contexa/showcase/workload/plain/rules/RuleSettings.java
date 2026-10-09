package io.contexa.showcase.workload.plain.rules;

import java.time.LocalTime;

/**
 * The adjustable values of the two rule controls (docs/showcase/데모-재설계.md H-10): what a visitor may tighten or
 * loosen in the rules scene, evaluated by the rule classes themselves over the facts a run recorded. {@link #FROZEN}
 * is the configuration the controls run with; every live decision uses it, so its reasons and outcomes are the ones
 * the runs recorded.
 *
 * @param nightStart    start of the night window of control C1 (company time)
 * @param nightEnd      end of the night window of control C1; equal to the start means no night window
 * @param volumeLimit   most items control C1 lets one export carry
 * @param dormant       control C1 refuses a project nobody of the requester's accesses touched in the window
 * @param external      control C2 refuses a request from neither an office network nor a registered trip
 * @param falseClaim    control C2 refuses a request that names a ticket the business database does not confirm
 * @param approval      control C2 accepts an approval that covers the project and the item count
 * @param ticket        control C2 accepts a fitting ticket (with on-call duty for an export, as the policy says)
 * @param assigned      control C2 accepts the assigned employee (the account manager for a customer)
 * @param assignedLimit most items an assigned employee exports without approval; null keeps the company's policy row
 * @param history       control C2 accepts recent work on the project for a document, as the policy says
 */
public record RuleSettings(LocalTime nightStart, LocalTime nightEnd, int volumeLimit, boolean dormant,
                           boolean external, boolean falseClaim, boolean approval, boolean ticket, boolean assigned,
                           Integer assignedLimit, boolean history) {

    /** The frozen configuration the rule controls run with (ADR-22, hashed into the rule version). */
    public static final RuleSettings FROZEN = new RuleSettings(ThresholdRules.NIGHT_START, ThresholdRules.NIGHT_END,
            ThresholdRules.VOLUME_LIMIT, true, true, true, true, true, true, null, true);

    /** Whether a company time falls in the night window; a window may wrap past midnight. */
    public boolean night(LocalTime time) {
        if (nightStart.equals(nightEnd)) {
            return false;
        }
        return nightStart.isAfter(nightEnd)
                ? !time.isBefore(nightStart) || time.isBefore(nightEnd)
                : !time.isBefore(nightStart) && time.isBefore(nightEnd);
    }
}
