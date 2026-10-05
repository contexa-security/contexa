/**
 * The privacy notice: only what the demo really does today, as recorded in docs/showcase/개인정보-데이터목록.md. The
 * demo asks the visitor for nothing (no account, no email, no consent step) and measures nothing (ADR-27).
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
          '체험에는 이름, 이메일, 계정이 필요 없습니다. 이용 흐름을 재는 측정이나 외부 분석 도구도 쓰지 않습니다.',
          '판정 엔진과 언어 모델에는 가상 회사의 직원, 요청, 업무 사실만 들어가고 방문자의 정보는 들어가지 않습니다.',
        ],
      },
      {
        heading: '처리하는 정보',
        table: [
          ['정보', '목적', '보관'],
          [
            '방문자 식별자(서명 쿠키 안 임의 값의 해시)',
            '장면마다 예측 한 번, 하루 실시간 실행 한도',
            '마지막 방문 뒤 30일. 그때 실행 기록에 붙은 해시도 지웁니다',
          ],
          ['예측 투표(장면, 허용·차단, 시각)', '끝 화면의 결과와 공유 카드의 점수', '방문자 식별자와 같음'],
          ['하루 한도 기록(방문자 해시, 날짜, 횟수)', '실시간 실행 비용 방어', '7일'],
          [
            '접속 주소의 날마다 바뀌는 키 해시(주소 원문은 저장하지 않음)',
            '쿠키를 지워도 동작하는 하루 한도',
            '7일',
          ],
          ['공유 카드(결과 숫자만)', '결과 공유', '마지막 공유 뒤 90일'],
        ],
      },
      {
        heading: '쿠키',
        table: [
          ['이름', '하는 일', '기간'],
          ['SC_VISITOR', '서명된 방문자 식별자. 예측 한 번, 하루 한도(스크립트에서 읽을 수 없음)', '30일'],
          ['XSRF-TOKEN', '다른 사이트가 이 데모에 요청을 보내는 것을 막음', '브라우저 세션'],
        ],
      },
      {
        heading: '자동 삭제와 외부 서비스',
        paragraphs: [
          '보관 기간이 지난 정보는 매일 03:30(UTC) 자동으로 지웁니다.',
          '실시간 실행에서만 사람 확인(Cloudflare Turnstile)을 씁니다. 가상 회사의 요청을 판정할 때 언어 모델 API를 부르지만 방문자의 정보는 보내지 않습니다.',
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
          'The experience needs no name, email or account. Nothing measures how you use the screens, and no outside analytics tool is used.',
          'The decision engine and the language model receive only the virtual company’s employees, requests and business facts, never information about you.',
        ],
      },
      {
        heading: 'What is processed',
        table: [
          ['Information', 'Purpose', 'Kept'],
          [
            'Visitor identifier (hash of a random value in a signed cookie)',
            'One prediction per scene, the daily live-run limit',
            '30 days after the last visit; the hash on run records is cleared then too',
          ],
          [
            'Prediction votes (scene, allow or block, time)',
            'The result on the end screen and the share card score',
            'As the visitor identifier',
          ],
          ['Daily limit records (visitor hash, date, count)', 'Cost protection for live runs', '7 days'],
          [
            'A keyed hash of the connecting address that changes daily (the address itself is not stored)',
            'A daily limit that still works when cookies are cleared',
            '7 days',
          ],
          ['Share cards (result numbers only)', 'Sharing a result', '90 days after the last share'],
        ],
      },
      {
        heading: 'Cookies',
        table: [
          ['Name', 'What it does', 'Lifetime'],
          [
            'SC_VISITOR',
            'Signed visitor identifier: one prediction, the daily limit (not readable by scripts)',
            '30 days',
          ],
          ['XSRF-TOKEN', 'Stops other sites from sending requests to this demo', 'Browser session'],
        ],
      },
      {
        heading: 'Automatic deletion and outside services',
        paragraphs: [
          'Information past its period is deleted automatically every day at 03:30 UTC.',
          'A human check (Cloudflare Turnstile) is used for live runs only. A language model API is called to decide the virtual company’s requests; no information about you is sent.',
        ],
      },
    ],
  },
};
