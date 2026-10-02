export const comparisonMessages = {
    'compare.operation': ['요청할 작업', 'Task to request'],
    'compare.operation.READ': ['화면에서 열람', 'Read on screen'],
    'compare.operation.DOWNLOAD': ['문서 파일 받기', 'Receive document file'],
    'compare.approval.scope': ['이 비교 요청에는 업무 승인을 연결하지 않습니다. 승인이 필요한 목적을 고르면 업무 규칙에 따라 거부될 수 있습니다.', 'These comparison requests do not include a work approval. A purpose requiring approval may be denied by the business rules.'],
    'compare.resource.type': ['업무 종류', 'Task type'],
    'compare.resource.DOCUMENT': ['문서 열람', 'Read a document'],
    'compare.resource.CUSTOMER': ['고객 정보 확인', 'Review a customer'],
    'compare.source.id': ['원본 식별자', 'Source ID'],
    'sessions.check.business-resources': ['업무 자료 원본', 'Business resource source'],
    'compare.check.business-resources': ['업무 자료 원본', 'Business resource source'],
    'compare.eyebrow': ['보안 비교 · 준비', 'Security comparison · preparation'],
    'compare.step.select': ['업무 선택', 'Choose a task'],
    'compare.step.verify': ['양쪽 조건 확인', 'Check both environments'],
    'compare.step.begin': ['실행 화면으로', 'Continue to the run'],
    'compare.choose.document': ['비교할 대상을 선택하세요', 'Choose the item to compare'],
    'compare.saved.document': ['기록에 저장된 업무 자료', 'Business resource in the saved record'],
    'compare.selected': ['선택한 업무', 'Selected task'],
    'compare.catalog.failed': ['업무 목록을 불러오지 못했습니다. 업무 환경의 로그인 상태를 확인한 뒤 다시 불러와 주세요.', 'The work catalog could not be loaded. Check your work sign-in, then reload the list.'],
    'compare.catalog.empty': ['선택할 수 있는 업무 자료가 없습니다.', 'No business resources are available to select.'],
    'compare.catalog.retry': ['업무 목록 다시 불러오기', 'Reload the work catalog'],
    'compare.sessions.heading': ['같은 출발 조건으로 비교', 'Compare from the same starting conditions'],
    'compare.conditions.details': ['확인한 계정·환경·이력 보기', 'View the checked accounts, environments and history'],
    'compare.preparation.details': ['저장 당시의 원본·기반 검사 기록', 'Source and foundation checks captured at preparation'],
    'compare.next.heading': ['다음 단계', 'Next step'],
    'compare.baseline.role': ['로그인과 기존 접근 권한을 확인하는 업무 환경입니다.', 'Work environment with sign-in and existing access checks.'],
    'compare.contexa.role': ['기존 접근 확인에 더해, 인증 후의 활동과 문맥을 판단합니다.', 'Adds assessment of activity and context after sign-in.'],
    'compare.flow.unchecked': ['확인 전', 'Not checked'],
    'compare.flow.confirmed': ['현재 조건 확인됨', 'Current conditions checked'],
    'compare.flow.attention': ['확인이 더 필요합니다', 'Needs attention'],
    'compare.flow.select': ['비교할 업무와 목적을 선택하세요.', 'Choose the task and purpose to compare.'],
    'compare.flow.verify': ['양쪽의 실제 로그인과 업무 조건을 확인하면 실행 화면으로 이동할 수 있습니다.', 'Check the actual sign-ins and work conditions in both environments to continue.'],
    'compare.flow.resolve': ['아래 확인 항목을 해결한 뒤 현재 조건을 다시 확인하세요. 아직 업무는 실행되지 않았습니다.', 'Resolve the listed checks and check the current conditions again. No work has run yet.'],
    'compare.flow.next': ['실행 화면에서 같은 요청을 양쪽에 보내고 결과를 확인할 수 있습니다.', 'Continue to the run screen to send the same request to both environments and review the results.'],
    'sessions.modelOptions': ['모델 기본 설정', 'Model defaults'],
    'sessions.modelOptions.captured': ['조회값 보존 · 실제 요청 설정은 근거에서 확인', 'Read values saved; see request evidence for applied options'],
    'sessions.modelOptions.incomplete': ['설정 원본 확인 필요', 'Configuration source needs review'],
    'sessions.roleHistory': ['현재 역할 범위의 이력 수', 'History entries in the current role scope'],
    'sessions.check.role-scope-history': ['역할 범위 이력 원본', 'Role scope history source'],
    'sessions.state.NO_STORED_SCOPE_RETURNED': ['저장된 역할 범위 없음', 'No stored role scope returned'],
    'sessions.state.UNSUPPORTED': ['현재 구성에서 조회 미지원', 'Reading is unsupported in this configuration'],
    'sessions.state.UNRECOGNIZED_STORED_FORMAT': ['저장 형식 확인 필요', 'Stored format needs review'],
    'sessions.state.HISTORY_UNAVAILABLE': ['이력을 읽지 못함', 'History could not be read'],
    'sessions.state.SCAN_LIMIT_REACHED': ['조회 한도 도달 · 전체 확인 필요', 'Read limit reached; full history unconfirmed'],
    'sessions.sessionHistory': ['로그인 세션의 업무 이력 수', 'Work entries in this session'],
    'sessions.organization': ['조직의 학습 갱신 수', 'Organization baseline updates'],
    'sessions.organizationNotProvided': ['현재 인증 문맥에 조직 정보 없음', 'No organization in current authentication context'],
    'sessions.check.model-configuration': ['모델 설정 원본', 'Model configuration source'],
    'sessions.check.search-inventory': ['검색 저장소 원본', 'Search corpus source'],
    'sessions.check.context-history': ['기존 활동 이력', 'Existing activity history'],

    "compare.saved.plan": ["저장된 요청 조건", "Saved request conditions"],
    "compare.expired": ["체험 공간의 유효기간이 지났거나 아직 준비되지 않았습니다. 참여 상태를 확인해 주세요.", "The workspace has expired or has not been prepared. Check your participation status."],
    "compare.title": [
        "같은 업무에서 차이를 확인하세요",
        "See the difference on the same task"
    ],
    "compare.lead": [
        "업무와 목적을 고르고, 두 환경의 출발 조건을 확인합니다. 실제 업무 요청과 AI 분석은 다음 실행 단계에서 시작됩니다.",
        "Choose a task and purpose, then check the starting conditions in both environments. Actual work requests and AI analysis begin at the run step."
    ],
    "compare.link": [
        "비교 준비",
        "Prepare a comparison"
    ],
    "compare.plan": [
        "요청할 업무",
        "Task to request"
    ],
    "compare.document": [
        "비교할 대상",
        "Item to compare"
    ],
    "compare.document.note": [
        "업무 목록의 이름으로 선택합니다. 본문과 고객 연락처는 아직 열지 않습니다.",
        "Choose by name from the work catalog. Content and customer contacts stay closed."
    ],
    "compare.account": [
        "요청에 사용할 계정",
        "Requested account"
    ],
    "compare.account.note": [
        "계정 선택은 로그인 확인이 아닙니다. 실행 시 양쪽 실제 세션을 확인해야 합니다.",
        "Selecting an account does not confirm sign-in. Both actual sessions must be checked before execution."
    ],
    "compare.check": [
        "이 업무로 비교 준비",
        "Prepare this comparison"
    ],
    "compare.recheck": [
        "업무 조건 변경",
        "Change the task"
    ],
    "compare.retry": [
        "같은 명령 다시 확인",
        "Retry the same command"
    ],
    "compare.retry.note": [
        "응답을 확인하지 못했습니다. 같은 입력으로 다시 확인하면 저장된 기록을 이어서 받습니다.",
        "The response could not be confirmed. Retrying the same input retrieves its saved record."
    ],
    "compare.saved": [
        "준비 기록이 저장되었습니다. 아직 업무 요청은 실행하지 않았습니다.",
        "Preparation saved. No business request has been executed."
    ],
    "compare.result": [
        "준비 확인 결과",
        "Readiness result"
    ],
    "compare.blocked": [
        "실행 준비 미완료",
        "Not ready to run"
    ],
    "compare.match": [
        "같은 업무 자료 확인",
        "Business resources match"
    ],
    "compare.mismatch": [
        "원본 확인 필요",
        "Source check needed"
    ],
    "compare.plan.count": [
        "계획: 환경별 같은 업무 요청 1회",
        "Plan: the same work request once per environment"
    ],
    "compare.plan.note": [
        "이 수는 업무 요청 계획입니다. 실제 모델 호출 수는 엔진의 분석·재시도에 따라 별도로 확인합니다.",
        "This is the business request plan. Model calls depend on engine analysis and retries and are counted separately."
    ],
    "compare.version": [
        "자료 버전",
        "Resource version"
    ],
    "compare.hash": [
        "업무 원본 해시",
        "Business source hash"
    ],
    "compare.hash.note": [
        "해시는 원본의 동일성을 비교하는 값입니다. 문서 본문이나 고객 연락처는 이 화면으로 전달하지 않습니다.",
        "A hash compares source equality. Document content and customer contacts are not sent to this page."
    ],
    "compare.needs": [
        "실행 전에 필요한 확인",
        "Checks needed before execution"
    ],
    "compare.needs.note": [
        "필수 근거가 갖춰지면 같은 요청 계획으로 비교할 수 있습니다. 아래는 이 검사 시점의 상태입니다.",
        "The same request plan can be compared when required evidence is available. These are the states captured at check time."
    ],
    "compare.check.experiment-runner": [
        "양쪽 업무 요청의 실행 연결",
        "Execution of requests in both environments"
    ],
    "compare.check.observation-adapter": [
        "AI 전송·재시도 원본 연결",
        "AI transmission and retry evidence"
    ],
    "compare.check.authenticated-sessions": [
        "양쪽 실제 로그인과 권한 확인",
        "Actual sign-in and permissions in both environments"
    ],
    "compare.check.complete-manifest": [
        "모델·정책·이력 등 전체 실행 조건 고정",
        "Freeze all model, policy and history conditions"
    ],
    "compare.check.execution-readiness": [
        "실행 준비 검사 통과",
        "Pass execution readiness checks"
    ],
    "compare.check.documents": [
        "양쪽 업무 자료의 일치",
        "Matching business resources"
    ],
    "compare.check.worker": [
        "업무 서버 연결",
        "Business server connection"
    ],
    "compare.check.other": [
        "필수 구성 확인",
        "Required configuration check"
    ],
    "compare.state.NOT_IMPLEMENTED": [
        "연결 준비 중",
        "Integration pending"
    ],
    "compare.state.PARTIALLY_IMPLEMENTED": [
        "일부 연결 미완료",
        "Integration incomplete"
    ],
    "compare.state.NOT_OBSERVED": [
        "확인하지 않음",
        "Not checked"
    ],
    "compare.state.NOT_READY": [
        "미준비",
        "Not ready"
    ],
    "compare.state.NOT_MATCHED": [
        "미확인 또는 불일치",
        "Unknown or different"
    ],
    "compare.state.CAPTURED": [
        "원본 확인",
        "Source captured"
    ],
    "compare.state.NOT_FOUND": [
        "문서 없음",
        "Document not found"
    ],
    "compare.state.UNAVAILABLE": [
        "조회할 수 없음",
        "Unavailable"
    ],
    "compare.state.other": [
        "확인 필요",
        "Needs attention"
    ],
    "compare.environment": [
        "환경",
        "Environment"
    ],
    "compare.all": [
        "비교 전체",
        "Comparison"
    ],
    "compare.source": [
        "저장한 계획과 검사 원본",
        "Saved plan and check evidence"
    ],
    "compare.time": [
        "확인 시각",
        "Checked at"
    ],
    "compare.record": [
        "준비 기록",
        "Preparation record"
    ],
    "compare.scope": [
        "문서 열람 1건의 준비 기록이며, 완료된 비교 실행이나 AI 판단 결과가 아닙니다.",
        "This records preparation for one document read, not a completed comparison or AI decision."
    ],
    "compare.account.return": [
        "로그인 연결 확인",
        "Check account connections"
    ],
    "compare.changed": [
        "같은 명령의 입력이 바뀌었습니다. 새 검사 기록을 만들어 주세요.",
        "The input for this command has changed. Create a new check."
    ],
    "compare.forbidden": [
        "참여 자격과 배정된 계정을 확인해 주세요.",
        "Check your participation status and assigned account."
    ],
    "compare.absent": [
        "이 준비 기록을 조회할 수 없습니다.",
        "This preparation record is not available."
    ]
};
