package io.contexa.showcase.portal.orchestrator;

import io.contexa.showcase.portal.orchestrator.ControlSession.ChallengeTrace;
import io.contexa.showcase.portal.orchestrator.ControlSession.ReleaseTrace;

import java.io.IOException;
import java.time.Instant;

/**
 * Answers control D's additional check of a step (deck p.12): automatically for recordings, by the visitor when the
 * visitor runs a scenario live (docs/showcase/P3-설계.md 3절). Every answer is the run principal's own action in its
 * own session; nothing about the engine's decision is changed.
 */
@FunctionalInterface
public interface ChallengeResponder {

    ChallengeTrace respond(Challenge challenge);

    /**
     * Control D refused a step because the engine blocked the account (ADR-33). Recordings never ask for a release, so
     * the block stays in the record as the engine left it; a visitor running the scenario live may ask for one.
     */
    default ReleaseTrace release(Release release) {
        return ReleaseTrace.notAsked(release.blockedAt());
    }

    /**
     * @param classification the scenario's ground truth: NORMAL, THREAT or UNCERTAIN
     * @param challengedAt   when control D's answer with the check came back
     */
    record Challenge(String classification, Instant challengedAt, ChallengeActions actions) {
    }

    /**
     * @param classification the scenario's ground truth: NORMAL, THREAT or UNCERTAIN
     * @param blockedAt      when control D's answer with the block came back
     * @param username       the blocked run principal
     * @param approver       the run's security administrator, created on its first use
     */
    record Release(String classification, Instant blockedAt, String username, ReleaseActions actions,
                   Approver approver) {
    }

    /**
     * Recordings: the legitimate user reads the inbox and enters the code at once; an attacker holds the password and
     * the session but not the mailbox (R1 contract), and so does an uncertain actor.
     */
    ChallengeResponder AUTOMATIC = ChallengeResponder::automatic;

    private static ChallengeTrace automatic(Challenge challenge) {
        if (!"NORMAL".equals(challenge.classification())) {
            return ControlSession.abandoned(challenge.challengedAt());
        }
        Instant requested = null;
        Instant verified = null;
        try {
            int status = challenge.actions().requestCode();
            requested = Instant.now();
            if (status != 200 && status != 302) {
                return failed(challenge, "code request " + status, requested, null);
            }
            String code = challenge.actions().readCode().orElse(null);
            if (code == null) {
                return failed(challenge, "no code in the demo inbox", requested, null);
            }
            int verification = challenge.actions().submitCode(code);
            verified = Instant.now();
            if (verification != 200) {
                return failed(challenge, "code verification " + verification, requested, verified);
            }
            return new ChallengeTrace(true, null, challenge.challengedAt(), requested, verified,
                    challenge.actions().reissue());
        } catch (IOException e) {
            return failed(challenge, e.getClass().getSimpleName() + ": " + e.getMessage(), requested, verified);
        }
    }

    static ChallengeTrace failed(Challenge challenge, String reason, Instant requested, Instant verified) {
        return new ChallengeTrace(false, reason, challenge.challengedAt(), requested, verified, null);
    }
}
