import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { postJson } from '../../api/http';
import type { LiveRunView } from '../../api/types';

export type LiveAction =
  'code' | 'answer' | 'cancel' | 'release-start' | 'release-request' | 'release-approve';

/**
 * The visitor's actions on the current live run (the extra check, the release of a block). The answer becomes the
 * run's view at once; a refusal or a lost request is said on the screen instead of being dropped (the old console
 * dropped them, 조사 2026-10-31).
 */
export function useLiveActions() {
  const client = useQueryClient();
  const [failed, setFailed] = useState(false);
  async function act(action: LiveAction, body: Readonly<Record<string, string>> = {}): Promise<boolean> {
    setFailed(false);
    try {
      const response = await postJson<LiveRunView>(`/api/live/runs/current/${action}`, body);
      if (response.body && response.status < 300) {
        client.setQueryData(['live-run'], response.body);
        return true;
      }
    } catch {
      // The request got no answer; the screen says so below.
    }
    setFailed(true);
    return false;
  }
  return { act, failed };
}
