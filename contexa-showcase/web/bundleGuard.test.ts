import { describe, expect, it } from 'vitest';
import { findInternalMarkers } from './bundleGuard';

describe('internal address guard (P5-SEC-06)', () => {
  it('finds internal addresses, ports, databases, paths and headers', () => {
    expect(findInternalMarkers('fetch("http://127.0.0.1:19182/api")')).toEqual([
      'private or loopback address',
      'showcase port',
    ]);
    expect(findInternalMarkers('const d = "10.40.12.77"')).toEqual(['private or loopback address']);
    expect(findInternalMarkers('const d = "172.20.0.5"')).toEqual(['private or loopback address']);
    expect(findInternalMarkers('proxy("http://localhost:5180")')).toEqual(['localhost with a port']);
    expect(findInternalMarkers('jdbc:postgresql://db:46432/showcase_portal')).toEqual([
      'showcase port',
      'showcase database',
      'database URL',
    ]);
    expect(findInternalMarkers('"/internal/runs/x"')).toEqual(['internal workload path']);
    expect(findInternalMarkers('"/ops/recordings"')).toEqual(['operator path']);
    expect(findInternalMarkers('h.set("X-Showcase-Run", id)')).toEqual(['internal signature header']);
  });

  it('leaves visitor paths, public addresses and library constants alone', () => {
    expect(findInternalMarkers('fetch("/api/live/runs")')).toEqual([]);
    expect(findInternalMarkers('new URL(`http://localhost`)')).toEqual([]);
    expect(findInternalMarkers('const ip = "203.0.113.9"; const v = "172.32.1.1"')).toEqual([]);
    expect(findInternalMarkers('const items = 4831; const port = ":19280"')).toEqual([]);
  });
});
