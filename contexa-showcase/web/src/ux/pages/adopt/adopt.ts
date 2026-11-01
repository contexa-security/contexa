export const TABS = ['steps', 'shadow', 'retention', 'integration'] as const;
export type TabId = (typeof TABS)[number];

/** The old adoption screen's steps (`?step=`) and the tab that holds each now (ST-81). */
const OLD_STEPS: Readonly<Record<string, TabId>> = { attach: 'steps', on: 'shadow' };

/** The tab an address opens: `?tab=`, else an old `?step=`, else the integration steps (ST-82). */
export function tabOf(params: URLSearchParams): TabId {
  const asked = params.get('tab') as TabId | null;
  if (asked && TABS.includes(asked)) {
    return asked;
  }
  return OLD_STEPS[params.get('step') ?? ''] ?? 'steps';
}

/** The public places of the current release (README, release 0.1.0). */
export const LINKS = {
  repository: 'https://github.com/contexa-security/contexa',
  docs: 'https://docs.ctxa.ai',
  quickstart: 'https://github.com/contexa73/contexa-examples/tree/master/contexa-example-quickstart',
  legacy: 'https://github.com/contexa73/contexa-examples/tree/master/contexa-example-legacy-system',
} as const;

/** The real coordinates, annotations and settings of the current release (README, release 0.1.0). */
export const CODE = {
  dependency: `dependencies {
    implementation "ai.ctxa:spring-boot-starter-contexa:0.1.0"
}`,
  annotations: `@SpringBootApplication
@EnableAISecurity
public class MyApplication {
}

@Protectable(sync = true)
@PostMapping("/api/projects/{id}/exports")
public ExportJob export(@PathVariable String id) {
    return exports.start(id);
}`,
  shadow: `contexa:
  security:
    zerotrust:
      mode: SHADOW`,
  enforce: `contexa:
  security:
    zerotrust:
      mode: ENFORCE`,
} as const;
