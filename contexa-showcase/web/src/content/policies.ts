/**
 * The privacy notice: only what the demo really does today, as recorded in docs/showcase/개인정보-데이터목록.md. The
 * demo asks the visitor for nothing (no account, no email, no consent step) and uses no analytics tool (ADR-27); it
 * keeps where the visitor is so a return resumes there, keeps the lab's calls and assessments with their runs, and
 * counts the groups first opened only as anonymous daily numbers (ADR-35). The quiz, the share card and the per-scene
 * vote are gone (V-19); what is left of them is deleted on its period. Plain words throughout (P-20).
 */
export interface PolicySection {
  readonly heading: string;
  readonly paragraphs?: readonly string[];
  /** A table with a header row first. */
  readonly table?: readonly (readonly string[])[];
}

export interface PolicyDocument {
  readonly title: string;
  readonly sections: readonly PolicySection[];
}

export const PRIVACY: Readonly<Record<'ko' | 'en', PolicyDocument>> = {
  ko: {
    title: '개인정보 안내',
    sections: [
      {
        heading: '받지 않는 것',
        paragraphs: [
          '체험에는 이름, 이메일, 계정이 필요 없습니다. 외부 분석 도구는 쓰지 않습니다.',
          '각 그룹을 처음 연 횟수는 날짜별 건수로만 셉니다. 누가 열었는지는 남기지 않습니다.',
          'Contexa와 언어 모델에는 가상 회사의 직원, 요청, 업무 사실만 들어가고 방문자의 정보는 들어가지 않습니다.',
        ],
      },
      {
        heading: '처리하는 정보',
        table: [
          ['정보', '목적', '보관'],
          [
            '방문자 식별자(쿠키에 든 임의 값을 알아볼 수 없게 바꾼 값)',
            '진행 위치와 결과 예상 이어 보기, 하루 직접 보내기 한도',
            '마지막 방문 뒤 30일. 그때 보낸 요청 기록에 붙은 식별자도 지웁니다',
          ],
          [
            '진행 위치(경로, 그룹, 단계, 확인한 차이, 보내기 전 결과 예상, 처음 연 그룹)',
            '다시 들어오면 이어 보기, 당신이 한 일, 같은 방문자를 두 번 세지 않기',
            '방문자 식별자와 같음(방문자 식별자를 지울 때 함께 지웁니다)',
          ],
          [
            '실험실의 결과 예상과 판단 평가(보낸 요청, 고른 답과 이유, 시각)',
            '실험실 결과에 내 예상을 보이고, 판단 평가는 다른 방문자에게 건수로만 보이기',
            '그 요청 기록과 같음. 방문자 식별자를 지울 때 여기에 붙은 식별자도 지웁니다',
          ],
          [
            '날짜별 익명 건수(그룹별로 처음 연 횟수)',
            '방문자가 어느 그룹까지 보는지 확인',
            '30일. 방문자와 연결되는 값은 없습니다',
          ],
          ['하루 한도 기록(방문자 식별자, 날짜, 횟수)', '직접 보내기가 너무 많아지지 않게 막기', '7일'],
          [
            '접속 주소를 날마다 바뀌는 키로 알아볼 수 없게 바꾼 값(주소 자체는 저장하지 않음)',
            '쿠키를 지워도 동작하는 하루 한도',
            '7일',
          ],
        ],
      },
      {
        heading: '쿠키',
        table: [
          ['이름', '하는 일', '기간'],
          ['SC_VISITOR', '서명된 방문자 식별자. 진행 위치, 하루 한도(스크립트에서 읽을 수 없음)', '30일'],
          ['XSRF-TOKEN', '다른 사이트가 이 데모에 요청을 보내는 것을 막음', '브라우저를 닫을 때까지'],
        ],
      },
      {
        heading: '자동 삭제와 외부 서비스',
        paragraphs: [
          '보관 기간이 지난 정보는 매일 03:30(세계 표준시) 자동으로 지웁니다.',
          '전에 있던 이해 확인 문항, 결과 공유 카드, 상황별 예측은 이제 없습니다. 그때 남은 기록도 보관 기간이 지나면 지웁니다(문항 건수는 30일, 공유 카드는 마지막 공유 뒤 90일, 예측은 방문자 식별자와 함께).',
          '직접 보낼 때만 사람 확인(Cloudflare Turnstile)을 씁니다. 가상 회사의 요청을 판단할 때 언어 모델을 부르지만 방문자의 정보는 보내지 않습니다.',
        ],
      },
    ],
  },
  en: {
    title: 'Privacy notice',
    sections: [
      {
        heading: 'What is not collected',
        paragraphs: [
          'The experience needs no name, email or account. No outside analytics tool is used.',
          'How many visitors first open each group is counted only as daily numbers. Who opened it is not kept.',
          'Contexa and the language model receive only the virtual company’s employees, requests and business facts, never information about you.',
        ],
      },
      {
        heading: 'What is processed',
        table: [
          ['Information', 'Purpose', 'Kept'],
          [
            'Visitor identifier (a random value from a signed cookie, turned into a value that cannot be read back)',
            'Resuming your place and your predictions, the daily live-send limit',
            '30 days after the last visit; the identifier on request records is cleared then too',
          ],
          [
            'Where you are (route, group, step, differences seen, your prediction before sending, groups first opened)',
            'Resuming where you left, what you did, not counting the same visitor twice',
            'As the visitor identifier (deleted with it)',
          ],
          [
            'Your lab predictions and assessments (the request sent, the answer and reasons you chose, time)',
            'Showing your prediction on the lab result; assessments are shown to other visitors only as counts',
            'As the request record; the identifier on them is cleared when the visitor identifier is deleted',
          ],
          [
            'Anonymous daily numbers (how many first opened each group)',
            'Seeing how far visitors go',
            '30 days; nothing in them links to a visitor',
          ],
          [
            'Daily limit records (visitor identifier, date, count)',
            'Keeping live sends from growing too many',
            '7 days',
          ],
          [
            'The connecting address turned, with a key that changes daily, into a value that cannot be read back (the address itself is not stored)',
            'A daily limit that still works when cookies are cleared',
            '7 days',
          ],
        ],
      },
      {
        heading: 'Cookies',
        table: [
          ['Name', 'What it does', 'Lifetime'],
          [
            'SC_VISITOR',
            'Signed visitor identifier: where you are, the daily limit (not readable by scripts)',
            '30 days',
          ],
          ['XSRF-TOKEN', 'Stops other sites from sending requests to this demo', 'Until the browser closes'],
        ],
      },
      {
        heading: 'Automatic deletion and outside services',
        paragraphs: [
          'Information past its period is deleted automatically every day at 03:30 UTC.',
          'The understanding check, the result share card and the per-situation predictions of earlier versions are gone. What is left of them is deleted on its period too (the question counts after 30 days, share cards 90 days after the last share, predictions with the visitor identifier).',
          'A human check (Cloudflare Turnstile) is used for live sends only. A language model API is called to judge the virtual company’s requests; no information about you is sent.',
        ],
      },
    ],
  },
};
