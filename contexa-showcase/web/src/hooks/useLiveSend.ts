import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { postJson } from '../api/http';
import { useLiveConfig, useLiveRun, useVisitor } from '../api/queries';
import type { LiveRunView } from '../api/types';
import { refusalOf, type GateRefusal } from '../domain/live';
import { useTurnstile } from './useTurnstile';

const ACTIVE = new Set(['QUEUED', 'STARTING', 'RUNNING', 'CHALLENGE', 'AWAITING', 'BLOCKED']);

/** A start request's answer as the gate reads it: the run (or the visitor's earlier one), or a refusal reason. */
export interface StartAnswer {
  readonly status: number;
  readonly body: (LiveRunView & { readonly reason?: string }) | null;
}

export interface LiveSendOptions {
  /** How the run is started; the live address with the case by default. */
  readonly post?: (turnstileToken: string | null) => Promise<StartAnswer>;
  /** Whether a started run is the one sent; a run of the case by default (a lab run's case key is its composition). */
  readonly matches?: (run: LiveRunView) => boolean;
}

/**
 * Sending a live run of a case through the visitor's gate (the human check, the daily runs), the same on every screen
 * that sends one. The portal starts no new run while the visitor's earlier run is still going (it is still being
 * finished after its last answer, or waits for the visitor); it answers with that run. The screen then says so, keeps
 * watching that run, and sends again by itself the moment it has ended, so the visitor never has to guess.
 *
 * @param scenario the case to send
 * @param started  what the screen does once the run of this case has started (open the run step, or nothing)
 * @param options  another start address and its reading of the run (the lab's composed runs)
 */
export function useLiveSend(
  scenario: string,
  started: (run: LiveRunView) => void,
  options: LiveSendOptions = {},
) {
  const queryClient = useQueryClient();
  const visitor = useVisitor();
  const config = useLiveConfig();
  const live = useLiveRun(true);
  const [sending, setSending] = useState(false);
  const [refusal, setRefusal] = useState<GateRefusal | null>(null);
  const [waitingFor, setWaitingFor] = useState<string | null>(null);
  const {
    container: turnstileContainer,
    token: turnstileToken,
    required: turnstileRequired,
    reset: resetTurnstile,
  } = useTurnstile(config.data?.turnstileSiteKey ?? null);
  const ready =
    visitor.isSuccess && !(turnstileRequired && !turnstileToken) && !sending && waitingFor === null;

  async function send(prepare?: () => Promise<void>) {
    setSending(true);
    setRefusal(null);
    if (prepare) {
      await prepare();
    }
    const response: StartAnswer = options.post
      ? await options.post(turnstileToken)
      : await postJson<LiveRunView & { reason?: string }>('/api/live/runs', { scenario, turnstileToken });
    resetTurnstile();
    setSending(false);
    const body = response.body;
    const ours = body !== null && (options.matches ? options.matches(body) : body.scenario === scenario);
    if (response.status === 202 && body && ours) {
      setWaitingFor(null);
      queryClient.setQueryData(['live-run'], body);
      started(body);
    } else if (response.status === 202 && body) {
      // The visitor's earlier run is still going: watch it, then send again once it has ended.
      queryClient.setQueryData(['live-run'], body);
      setWaitingFor(body.liveRunId);
    } else {
      setWaitingFor(null);
      setRefusal(refusalOf(response.status, body?.reason ?? null));
    }
  }

  const earlier = live.data && live.data.liveRunId === waitingFor ? live.data : null;
  const earlierEnded = earlier !== null && !ACTIVE.has(earlier.status);
  useEffect(() => {
    if (waitingFor === null || !earlierEnded) {
      return undefined;
    }
    // The earlier run's end is an outside event: the run is sent again once, after this render.
    const timer = setTimeout(() => {
      setWaitingFor(null);
      void send();
    }, 0);
    return () => clearTimeout(timer);
    // `send` is recreated on every render; the earlier run's end is what matters.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [waitingFor, earlierEnded]);

  return {
    send,
    sending,
    ready,
    refusal,
    /** The visitor's earlier run is being finished; this run is sent the moment it has ended. */
    waiting: waitingFor !== null,
    turnstileContainer,
    turnstileRequired,
  };
}
