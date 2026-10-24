package io.contexa.showcase.portal.orchestrator;

import io.contexa.showcase.portal.orchestrator.ControlSession.AgentConfirmationTrace;
import io.contexa.showcase.portal.orchestrator.ControlSession.ChallengeTrace;
import io.contexa.showcase.portal.orchestrator.ControlSession.ReleaseTrace;
import io.contexa.showcase.portal.orchestrator.ControlSession.StepOutcome;

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
     * docs/agent A7-3: control D asked the delegating person to confirm an agent's request (A5-2). Recordings give no
     * answer unless a run asks for one; a visitor running the case live answers as the delegating employee.
     */
    default AgentConfirmationTrace confirmAgent(AgentConfirmation confirmation) {
        return AgentConfirmationTrace.notAsked(confirmation.confirmationId(), confirmation.trigger(),
                confirmation.expiresAt(), confirmation.askedAt());
    }

    /**
     * @param classification the scenario's ground truth: NORMAL, THREAT or UNCERTAIN
     * @param challengedAt   when control D's answer with the check came back
     */
    record Challenge(String classification, boolean ownerActs, Instant challengedAt, ChallengeActions actions) {

        /** A challenge of a case whose actor is who its classification says (an attacker, or the owner at work). */
        public Challenge(String classification, Instant challengedAt, ChallengeActions actions) {
            this(classification, false, challengedAt, actions);
        }
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
     * docs/agent A7-3: a confirmation control D asked of an agent's request.
     *
     * @param stepNo  the step of the agent's request
     * @param trigger why the engine asked (DELEGATION_ENDED, DECISION_CHALLENGE, ...)
     * @param askedAt when control D's answer with the confirmation came back
     */
    record AgentConfirmation(String classification, int stepNo, String confirmationId, String trigger,
                             String expiresAt, Instant askedAt, String method, String target,
                             AgentConfirmationActions actions) {
    }

    /**
     * docs/agent A7-3, DD-27: a recording in which the delegating person gives the same answer to every confirmation
     * (the operator's check of the confirmation flow); {@code retries} is how often the agent sends its request again
     * while the confirmation goes unanswered (SILENT). Its other answers are the recordings' own.
     */
    static ChallengeResponder deciding(DelegatorAnswer answer, int retries) {
        return new ChallengeResponder() {
            @Override
            public ChallengeTrace respond(Challenge challenge) {
                return AUTOMATIC.respond(challenge);
            }

            @Override
            public AgentConfirmationTrace confirmAgent(AgentConfirmation confirmation) {
                return answer(confirmation, answer, retries, AgentRetryStorm.Pause.SLEEP);
            }
        };
    }

    /** docs/agent A7-3: a visitor's answer as the delegating employee, approval or rejection. */
    static AgentConfirmationTrace answer(AgentConfirmation confirmation, boolean approve) {
        return answer(confirmation, approve ? DelegatorAnswer.APPROVE : DelegatorAnswer.REJECT, 0,
                AgentRetryStorm.Pause.SLEEP);
    }

    /**
     * docs/agent A7-3, DD-27: the person's answer and what follows it.
     * <ul>
     * <li>APPROVE: the agent first offers the approval for another request, which the engine must refuse while the
     * approval is still unused (A5-9), then sends the approved request again with it, then once more, which the
     * engine must refuse as well (one use).</li>
     * <li>REJECT: the agent's request sent again with it must be refused.</li>
     * <li>REPORT: the engine blocks and stops the agent (A5-2, A5-3): its request sent again must be refused, while
     * the person's own same request still goes on, the person's decisions not being the agent's (A5-1).</li>
     * <li>SILENT: no answer; the agent sends its request again {@code retries} times at once and once more after the
     * wait the call limit asks for (A5-7), then the person sends the same request.</li>
     * </ul>
     */
    static AgentConfirmationTrace answer(AgentConfirmation confirmation, DelegatorAnswer answer, int retries,
                                         AgentRetryStorm.Pause pause) {
        AgentConfirmationActions actions = confirmation.actions();
        Instant decidedAt = null;
        Integer decided = null;
        try {
            if (answer == DelegatorAnswer.SILENT) {
                ControlSession.RetryStorm storm = AgentRetryStorm.run(actions, retries, pause);
                StepOutcome person = actions.personRequest();
                return new AgentConfirmationTrace(confirmation.confirmationId(), confirmation.trigger(),
                        confirmation.expiresAt(), answer.name(), null, confirmation.askedAt(), null, null, null,
                        null, null, null, person, storm);
            }
            decided = actions.decide(answer);
            decidedAt = Instant.now();
            ControlSession.AgentConfirmationStatus after = actions.status();
            boolean approved = answer == DelegatorAnswer.APPROVE;
            StepOutcome other = approved ? actions.resendOther() : null;
            StepOutcome resend = actions.resend();
            StepOutcome reuse = approved ? actions.resend() : null;
            StepOutcome person = answer == DelegatorAnswer.REPORT ? actions.personRequest() : null;
            return new AgentConfirmationTrace(confirmation.confirmationId(), confirmation.trigger(),
                    confirmation.expiresAt(), answer.name(), null, confirmation.askedAt(), decidedAt, decided,
                    after, resend, reuse, other, person, null);
        } catch (IOException | RuntimeException e) {
            return failed(confirmation, answer, e.getClass().getSimpleName() + ": " + e.getMessage(), decidedAt,
                    decided);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return failed(confirmation, answer, "InterruptedException", decidedAt, decided);
        }
    }

    private static AgentConfirmationTrace failed(AgentConfirmation confirmation, DelegatorAnswer answer,
                                                 String reason, Instant decidedAt, Integer decided) {
        return new AgentConfirmationTrace(confirmation.confirmationId(), confirmation.trigger(),
                confirmation.expiresAt(), answer.name(), reason, confirmation.askedAt(), decidedAt, decided, null,
                null, null, null, null, null);
    }

    /**
     * Recordings: the legitimate user reads the inbox and enters the code at once; an attacker holds the password and
     * the session but not the mailbox (R1 contract), and so does an uncertain actor. An insider is the account's owner
     * (IN-6): the code reaches their own mailbox, so they enter it as the legitimate user does.
     */
    ChallengeResponder AUTOMATIC = ChallengeResponder::automatic;

    private static ChallengeTrace automatic(Challenge challenge) {
        if (!"NORMAL".equals(challenge.classification()) && !challenge.ownerActs()) {
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
