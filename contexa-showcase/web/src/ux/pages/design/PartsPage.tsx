import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { applyTheme, useTheme } from '../../theme';
import {
  Badge,
  Bar,
  Breadcrumbs,
  Button,
  ButtonLink,
  Card,
  CodeChip,
  DataTable,
  DetailGroup,
  DetailPanel,
  Drawer,
  EmptyState,
  ErrorState,
  EvalBadge,
  Field,
  FlagBadge,
  KeyValue,
  Kpi,
  Loading,
  Modal,
  Note,
  PageHead,
  Range,
  Select,
  StackedBar,
  Stepper,
  SummaryBar,
  Switch,
  TabPanel,
  Tabs,
  TextInput,
  VerdictBadge,
} from '../../ui';
import styles from './PartsPage.module.css';

/**
 * Development-only gallery of the new screens' parts and their states (UX-R1 I-1), for measuring the type sizes,
 * button heights and colours in both themes and both languages. Every value here is a sample and says so; Vite leaves
 * this page out of the production bundle. `?theme=light` opens it in the light theme.
 */
const SAMPLE = '예시 · sample';

const CONTROLS = [
  { id: 'waf', name: '웹 방화벽', blocked: 0, ms: 41 },
  { id: 'iam', name: '인증 · 권한', blocked: 0, ms: 12 },
  { id: 'contexa', name: 'Contexa', blocked: 3, ms: 10169 },
] as const;

export default function PartsPage() {
  const { t, i18n } = useTranslation();
  const [params] = useSearchParams();
  const { theme, toggle } = useTheme();
  const [tab, setTab] = useState('result');
  const [on, setOn] = useState(true);
  const [threshold, setThreshold] = useState(5);
  const [modal, setModal] = useState(false);
  const [drawer, setDrawer] = useState(false);
  const wanted = params.get('theme');
  useEffect(() => {
    if (wanted === 'light' || wanted === 'dark') {
      applyTheme(wanted);
    }
  }, [wanted]);
  return (
    <main id="main" className={styles.page}>
      <div className={styles.bar}>
        <Breadcrumbs items={[{ label: 'Design', to: '/design/ux' }, { label: t('ux.parts.title') }]} />
        <Button size="sm" icon={theme === 'dark' ? 'sun' : 'moon'} onClick={toggle}>
          {theme}
        </Button>
        <Button
          size="sm"
          icon="globe"
          onClick={() => void i18n.changeLanguage(i18n.language === 'ko' ? 'en' : 'ko')}
        >
          {i18n.language.toUpperCase()}
        </Button>
      </div>

      <PageHead
        kicker={
          <>
            <Badge tone="line" icon="user-round-x">
              {SAMPLE}
            </Badge>
            <CodeChip value="S13" />
          </>
        }
        title={t('ux.parts.title')}
        status={<VerdictBadge verdict="CHALLENGE" />}
        desc={t('ux.parts.desc')}
        actions={
          <>
            <Button icon="list-checks">Secondary</Button>
            <Button variant="primary" icon="play">
              Primary
            </Button>
          </>
        }
      />

      <Stepper steps={['시나리오 확인', '실행', '판정 결과', '같은 요청 비교']} current={2} />

      <Tabs
        idBase="parts"
        label="parts tabs"
        value={tab}
        onChange={setTab}
        items={[
          { id: 'result', label: '판정 결과' },
          { id: 'facts', label: '인용 사실', count: 10 },
          { id: 'seal', label: '무결성 검증' },
        ]}
      />
      <TabPanel idBase="parts" id={tab}>
        <div className={styles.grid}>
          <Kpi icon="activity" label="누적 판정" value="13,733" unit="건" foot={SAMPLE} />
          <Kpi icon="timer" label="판정 시간 p50" value="6.0" unit="초" foot={SAMPLE} />
          <Kpi icon="users" label="방문자 실행" value="2,046" unit="회" foot={SAMPLE} />
          <Kpi icon="shield-check" label="응답 전 보류" value="613" unit="건" foot={SAMPLE} />
        </div>
      </TabPanel>

      <SummaryBar
        label="summary"
        items={[
          { label: '판정', value: <VerdictBadge verdict="CHALLENGE" showCode /> },
          { label: '위험도', value: '0.43' },
          { label: '확신도', value: '0.78' },
          { label: '판정 시간', value: '10.2초' },
          { label: '실행 ID', value: <CodeChip value="run-04cdd89264f7" copy /> },
        ]}
      />

      <div className={styles.columns}>
        <div className={styles.stack}>
          <Card title="Buttons" sub={SAMPLE}>
            <div className={styles.rows}>
              {(['sm', 'md', 'lg'] as const).map((size) => (
                <div key={size} className={styles.row}>
                  <Button size={size} variant="primary" icon="play">
                    요청 실행
                  </Button>
                  <Button size={size} icon="list-checks">
                    판정 이력
                  </Button>
                  <Button size={size} variant="text" iconAfter="arrow-right">
                    자세히
                  </Button>
                  <Button size={size} variant="danger" icon="ban">
                    실행 취소
                  </Button>
                </div>
              ))}
              <div className={styles.row}>
                <Button variant="primary" disabledReason="오늘 실행 한도 도달 (sample)">
                  요청 실행
                </Button>
                <Button busy>요청 실행</Button>
                <ButtonLink to="/design/ux" iconAfter="arrow-right">
                  Link
                </ButtonLink>
              </div>
            </div>
          </Card>

          <Card title="Badges" sub={SAMPLE}>
            <div className={styles.rows}>
              <div className={styles.row}>
                <VerdictBadge verdict="ALLOW" />
                <VerdictBadge verdict="CHALLENGE" />
                <VerdictBadge verdict="ESCALATE" />
                <VerdictBadge verdict="BLOCK" />
                <VerdictBadge verdict="PENDING" />
                <VerdictBadge verdict="NONE" />
              </div>
              <div className={styles.row}>
                <EvalBadge result="correct" />
                <EvalBadge result="normal" />
                <EvalBadge result="partial" />
                <EvalBadge result="missed" />
                <EvalBadge result="falsePositive" />
              </div>
              <div className={styles.row}>
                <FlagBadge />
                <Badge tone="line" icon="bot">
                  AI 에이전트
                </Badge>
                <Badge tone="brand">Contexa</Badge>
                <Badge tone="sel">선택</Badge>
                <CodeChip value="4a1527…a9d0" />
              </div>
            </div>
          </Card>

          <Card title="통제별 차단" sub={SAMPLE} flush>
            <DataTable
              caption="controls"
              rows={CONTROLS}
              rowKey={(row) => row.id}
              selected="iam"
              highlighted={(row) => row.id === 'contexa'}
              columns={[
                { key: 'name', header: '통제', strong: true, render: (row) => row.name },
                { key: 'blocked', header: '차단', numeric: true, render: (row) => row.blocked },
                {
                  key: 'ms',
                  header: '판정 시간(ms)',
                  numeric: true,
                  render: (row) => row.ms.toLocaleString('ko-KR'),
                },
              ]}
            />
          </Card>

          <Card title="판정 이력" sub={SAMPLE} flush>
            <DataTable
              caption="log"
              stack
              rows={CONTROLS}
              rowKey={(row) => row.id}
              columns={[
                { key: 'name', header: '시나리오', strong: true, render: (row) => row.name },
                {
                  key: 'verdict',
                  header: '판정',
                  render: (row) => <VerdictBadge verdict={row.blocked > 0 ? 'CHALLENGE' : 'ALLOW'} />,
                },
                {
                  key: 'eval',
                  header: '평가',
                  render: (row) => <EvalBadge result={row.blocked > 0 ? 'correct' : 'missed'} />,
                },
              ]}
            />
          </Card>

          <Card title="Distribution" sub={SAMPLE}>
            <div className={styles.rows}>
              <Bar label="위험도" value={0.43} />
              <StackedBar
                label="판정 분포"
                format={(value) => value.toLocaleString('ko-KR')}
                segments={[
                  { label: '허용', value: 9932, tone: 'allow' },
                  { label: '추가 인증', value: 2148, tone: 'stepup' },
                  { label: '검토 보류', value: 1136, tone: 'hold' },
                  { label: '차단', value: 517, tone: 'block' },
                ]}
              />
              <StackedBar
                label="통제"
                format={(value) => String(value)}
                segments={[
                  { label: '웹 방화벽', value: 1, tone: 'waf' },
                  { label: '인증 · 권한', value: 1, tone: 'iam' },
                  { label: '임계값 규칙', value: 1, tone: 'rule' },
                  { label: '승인 정책 규칙', value: 1, tone: 'approval' },
                  { label: 'Contexa', value: 1, tone: 'brand' },
                ]}
              />
            </div>
          </Card>

          <Card title="States" sub={SAMPLE}>
            <div className={styles.rows}>
              <Loading rows={2} />
              <EmptyState />
              <ErrorState onRetry={() => undefined} />
            </div>
          </Card>
        </div>

        <div className={styles.stack}>
          <DetailPanel
            title="run-04cdd89264f7"
            onClose={() => undefined}
            footer={
              <>
                <Button>판정 상세</Button>
                <Button variant="text">비교</Button>
              </>
            }
          >
            <DetailGroup title="판정">
              <KeyValue
                items={[
                  { label: '판정', value: <VerdictBadge verdict="CHALLENGE" /> },
                  { label: '모델', value: 'gpt-6-luna' },
                  { label: '기준선', value: <FlagBadge /> },
                ]}
              />
            </DetailGroup>
            <DetailGroup title="수치">
              <KeyValue
                alignEnd
                items={[
                  { label: '입력', value: '6,787' },
                  { label: '출력', value: '704' },
                ]}
              />
            </DetailGroup>
          </DetailPanel>

          <Card title="Inputs" sub={SAMPLE}>
            <div className={styles.rows}>
              <Field label="실행 ID" hint={SAMPLE}>
                {(props) => <TextInput {...props} placeholder="run-…" />}
              </Field>
              <Field label="시나리오">
                {(props) => (
                  <Select {...props}>
                    <option>S13</option>
                    <option>S13T</option>
                  </Select>
                )}
              </Field>
              <Range label="건수 임계값" min={1} max={10} value={threshold} onChange={setThreshold} />
              <Switch label="휴면 계정 조건" checked={on} onChange={setOn} />
            </div>
          </Card>

          <Note>표본 41개 시나리오 × 5회 ({SAMPLE})</Note>
          <Note tone="warn">이 숫자는 이전 빌드의 측정입니다 ({SAMPLE})</Note>

          <Card title="Layers" sub={SAMPLE}>
            <div className={styles.row}>
              <Button onClick={() => setModal(true)}>Modal</Button>
              <Button onClick={() => setDrawer(true)}>Drawer</Button>
            </div>
          </Card>
        </div>
      </div>

      <Modal
        open={modal}
        onClose={() => setModal(false)}
        title="동일 요청 60건 전송"
        footer={
          <>
            <Button variant="text" onClick={() => setModal(false)}>
              취소
            </Button>
            <Button variant="primary" onClick={() => setModal(false)}>
              전송
            </Button>
          </>
        }
      >
        실제 판정 비용이 듭니다 ({SAMPLE}).
      </Modal>
      <Drawer open={drawer} side="start" title="Contexa" onClose={() => setDrawer(false)}>
        {SAMPLE}
      </Drawer>
    </main>
  );
}
