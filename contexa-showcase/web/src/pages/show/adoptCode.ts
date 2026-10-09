/**
 * The code of scene 5 (docs/showcase/화면설계서.md): the lines of this demo's own workload that turn Contexa on and
 * protect the export the visitor just sent. They are copied from the source files named here, and a test checks that
 * the source still holds them line for line.
 */
export interface CodeExcerpt {
  readonly path: string;
  readonly lines: readonly string[];
  /** Index of the line to highlight. */
  readonly highlight: number;
}

export const ADOPT_CODE: readonly CodeExcerpt[] = [
  {
    path: 'showcase-workload-contexa/src/main/java/io/contexa/showcase/workload/contexa/ContexaWorkloadApplication.java',
    lines: [
      '@EnableAISecurity(mode = SecurityMode.FULL)',
      '@EnableShowcaseInternalContext',
      '@EnableShowcaseBusiness',
      'public class ContexaWorkloadApplication {',
    ],
    highlight: 0,
  },
  {
    path: 'showcase-workload-contexa/src/main/java/io/contexa/showcase/workload/contexa/business/ContexaBusinessOperations.java',
    lines: [
      '    @Protectable',
      '    public ExportStream openExportStream(BusinessRequest request, String projectKey, int items) {',
      '        return delegate.openExportStream(request, projectKey, items);',
      '    }',
    ],
    highlight: 0,
  },
];
