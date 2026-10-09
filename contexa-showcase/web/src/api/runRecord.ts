import { getJson } from './http';

/**
 * Downloads the stored records of a step (anatomy, score, the prompts and answers sent to the engine) as one JSON file
 * and returns the SHA-256 of that file, so anyone can check it outside the demo (docs/showcase/데모-재설계.md 3).
 * Session identifiers are already masked by the portal.
 */
export async function downloadRunRecord(runId: string, stepNo: number, anatomy?: unknown): Promise<string> {
  const base = `/api/runs/${encodeURIComponent(runId)}`;
  const [record, score, exchanges] = await Promise.all([
    anatomy === undefined ? getJson<unknown>(`${base}/steps/${stepNo}/anatomy`) : Promise.resolve(anatomy),
    getJson<unknown>(`${base}/score`),
    getJson<unknown>(`${base}/steps/${stepNo}/exchanges`),
  ]);
  const text = JSON.stringify({ anatomy: record, score, exchanges }, null, 1);
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  const hash = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  link.download = `${runId}-step${stepNo}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
  return hash;
}
