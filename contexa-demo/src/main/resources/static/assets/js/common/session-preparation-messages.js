export const sessionPreparationMessages = {
    "sessions.recovery.return": [
        "새 창에서 확인을 마친 뒤 이 화면에서 조건을 새로 확인하세요. 업무 요청은 자동으로 실행되지 않습니다.",
        "Complete the check in the new tab, return here and check the current conditions again. Work does not run automatically."
    ],
    'sessions.models': ['등록된 분석 모델', 'Registered chat models'],
    'sessions.corpus': ['검색 자료 수', 'Stored documents'],
    'sessions.corpus.note': ['자료 수는 저장소 확인값입니다. 실제 검색되거나 판단에 사용된 자료 수는 각 요청의 근거에서 확인합니다.', 'This count describes stored documents. Inspect request evidence for documents actually retrieved or used in a decision.'],
    "sessions.title": [
        "양쪽 로그인 확인",
        "Check both signed-in sessions"
    ],
    "sessions.lead": [
        "업무 서버가 현재 계정·권한과 선택한 업무 자료를 직접 확인합니다.",
        "Each business server checks the current account, permissions and selected business resource."
    ],
    "sessions.capture": [
        "현재 로그인·조건 확인",
        "Check current sessions & conditions"
    ],
    "sessions.retry": [
        "같은 확인 이어받기",
        "Resume the same check"
    ],
    "sessions.renew": [
        "새 시점으로 다시 확인",
        "Check at a new time"
    ],
    "sessions.renewNote": [
        "이전 원본은 보존됩니다. 버튼을 눌러 현재 조건을 새 기록으로 확인하세요.",
        "Previous evidence is preserved. Check current conditions to create a new record."
    ],
    "sessions.matched": [
        "초기 조건 일치",
        "Initial conditions match"
    ],
    "sessions.incomplete": [
        "추가 확인 필요",
        "Further checks needed"
    ],
    "sessions.result": [
        "서버가 확인한 조건",
        "Server-observed conditions"
    ],
    "sessions.account": [
        "로그인 계정",
        "Signed-in account"
    ],
    "sessions.permissions": [
        "계정의 원래 권한",
        "Original account permissions"
    ],
    "sessions.captured": [
        "실제 확인 시각",
        "Observed at"
    ],
    "sessions.history": [
        "엔진 이력 갱신 수",
        "Native history updates"
    ],
    "sessions.noAI": [
        "AI 비활성 환경",
        "AI disabled"
    ],
    "sessions.historyUnknown": [
        "갱신 수 확인 안 됨",
        "Update count not observed"
    ],
    "sessions.saved": [
        "양쪽 서버의 확인 원본을 저장했습니다. 업무 요청은 아직 발행하지 않았습니다.",
        "Saved observations from both servers. No business request has been issued."
    ],
    "sessions.signinNeeded": [
        "로그인 또는 추가 본인 확인이 필요합니다. 아래 안내에서 해당 환경을 확인한 뒤 계속하세요.",
        "Sign-in or additional verification is needed. Follow the action below for the affected environment, then continue."
    ],
    "sessions.failed": [
        "한쪽 확인이 완료되지 않았습니다. 저장된 원본은 보존되며 같은 확인을 다시 이어받을 수 있습니다.",
        "A check did not finish. Saved sources are preserved; you can resume the same check."
    ],
    "sessions.scope": [
        "확인 당시의 조건입니다. 2분이 지나면 실행 전에 다시 확인해야 합니다. 실제 요청 시에도 인증·업무 검사는 유지됩니다. 이력 갱신 수는 정확도나 학습 완료율이 아닙니다. 전체 실행 조건과 실행 연결은 별도로 확인합니다.",
        "These conditions were observed at the displayed time and must be checked again after two minutes. Authentication and business checks still apply to actual requests. History updates are not accuracy or learning completion. Full execution conditions and dispatch are checked separately."
    ],
    "sessions.source": [
        "로그인·업무 자료·설정 원본 보기",
        "Inspect session, business resource and configuration sources"
    ],
    "sessions.check.authenticated-sessions": [
        "실제 로그인",
        "Actual sign-in"
    ],
    "sessions.check.authentication-progress": [
        "진행 중 인증",
        "Authentication progress"
    ],
    "sessions.check.authentication-level": [
        "인증 방식",
        "Authentication method"
    ],
    "sessions.check.account-permissions": [
        "계정 권한",
        "Account permissions"
    ],
    "sessions.check.documents": [
        "문서 원본",
        "Document source"
    ],
    "sessions.check.business-resources": [
        "선택한 업무 자료",
        "Selected business resource"
    ],
    "sessions.check.static-policy": [
        "공통 접근 정책",
        "Shared access policy"
    ],
    "sessions.check.assignments": [
        "담당 프로젝트",
        "Assigned projects"
    ],
    "sessions.check.application-version": [
        "애플리케이션 버전",
        "Application version"
    ],
    "sessions.check.history": [
        "기존 엔진 이력",
        "Existing native history"
    ],
    "sessions.check.runtime-security": [
        "보안 환경 설정",
        "Security environment"
    ],
    "sessions.check.other": [
        "초기 조건",
        "Initial condition"
    ],
    "sessions.state.NOT_OBSERVED": [
        "미확인",
        "Not observed"
    ],
    "sessions.state.STALE": [
        "다시 확인 필요",
        "Check again"
    ],
    "sessions.state.NOT_READY": [
        "준비 미완료",
        "Not ready"
    ],
    "sessions.state.NOT_MATCHED": [
        "불일치",
        "Does not match"
    ],
    "sessions.state.CHANGED": [
        "준비 이후 변경됨",
        "Changed since preparation"
    ],
    "sessions.state.UNAVAILABLE": [
        "확인 불가",
        "Unavailable"
    ],
    "sessions.state.NOT_FOUND": [
        "원본 없음",
        "Source missing"
    ],
    "sessions.state.other": [
        "추가 확인 필요",
        "Further check needed"
    ],
    "sessions.role.ROLE_INFRA": [
        "인프라 업무",
        "Infrastructure work"
    ],
    "sessions.role.ROLE_USER": [
        "일반 업무",
        "General work"
    ],
    "sessions.role.ROLE_ADMIN": [
        "운영 관리",
        "Administration"
    ]
};
