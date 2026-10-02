export const workMessages = {
    'work.unavailable.here': ['이 참여 세션에서 열 수 있는 자료나 기록을 찾지 못했습니다. 업무 목록에서 자료를 선택하거나, 해당 요청의 근거 링크를 다시 열어 주세요.', 'This resource or record is not available in your participation session. Select it from the work list or reopen the evidence link for your request.'],
    'work.reopen.list': ['업무 목록으로 돌아가기', 'Return to the work list'],
    'export.security.title': ['파일 생성 전 보안 확인', 'Security check before file creation'],
    'export.security.note': ['이 내보내기는 Contexa의 동기 보호를 사용합니다. 필요한 보안 분석을 기다린 뒤 허용된 경우 파일을 만듭니다. 이미 유효한 판단이 있으면 엔진이 재사용할 수 있습니다.', 'This export uses Contexa’s synchronous protection. It waits for any required security analysis before creating an allowed file. The engine may reuse an existing valid decision.'],
    'work.block.mfa': ['업무가 제한되어 있습니다. Contexa의 본인 확인을 진행해 주세요.', 'Work is restricted. Continue with Contexa identity verification.'],
    'work.block.required': ['업무 접근이 차단되었습니다. 보안 안내에서 해제 요청 절차를 확인해 주세요.', 'Work access is blocked. Open the security notice for the review request process.'],
    'work.review.required': ['Contexa가 추가 검토 중입니다. 보안 안내에서 진행 상태를 확인해 주세요.', 'Contexa is reviewing this activity. Open the security notice to check progress.'],
    'work.security.notice': ['보안 안내 확인', 'Open security notice'],
    'work.event.MODEL_EXECUTION': ['모델 호출 단계 종료', 'Model call step completed'],
    'work.pipeline.note': ['엔진이 남긴 응답 검사와 재시도 기록입니다. 최종 보안 결정은 아래에서 별도로 확인하세요.', 'Native response-validation and retry metadata. Inspect the final security decision separately below.'],
    'work.history.title': ['판단에 참고한 이력', 'History considered for analysis'],
    'work.history.boundary': ['엔진의 입력 후보에 연결된 이력을 분석 단계가 끝날 때 읽은 기록입니다. 실제 모델 전송 내용과 학습 완료 여부는 별도 확인이 필요합니다.', 'History linked to a generated input candidate, read when the analysis layer completed. Actual model transmission and completed learning require separate evidence.'],
    'work.history.missing': ['이 요청의 이력 상세를 수집하지 못했습니다. 이력이 없다는 뜻은 아닙니다.', 'History details were not captured for this request. This does not mean that no history exists.'],
    'work.history.personal': ['개인 업무 이력', 'Personal work history'],
    'work.history.organization': ['조직 참고 이력', 'Organization reference history'],
    'work.history.established': ['엔진 기준 충족', 'Engine criteria met'],
    'work.history.available': ['이력 있음 · 기준 미충족', 'Available · criteria not yet met'],
    'work.history.absent': ['참고 가능한 이력 없음', 'No available history'],
    'work.history.updates': ['기준 이력 갱신 수', 'Baseline update count'],
    'work.history.requests': ['세션 요청 수', 'Session request count'],
    'work.history.references': ['입력 후보의 참고 기록 수', 'References attached to input candidate'],
    'work.history.counts.note': ['횟수는 정확도나 학습 완성도를 뜻하지 않습니다. 참고 기록 수만으로 검색 성공·실패를 판단할 수 없습니다.', 'Counts do not measure accuracy or learning maturity. Reference counts alone do not establish search success or failure.'],
    'work.history.truncated': ['참고 기록 상세는 최대 20건까지 표시합니다. 전체 수는 위에 표시됩니다.', 'Reference details are limited to 20 entries. The full count is shown above.'],
    'work.history.source': ['이력 출처와 참조 식별 보기', 'View history source and reference identifiers'],
    'work.collection.details': ['기록 수집 상태 보기', 'View collection status'],
    'work.collection.scope': ['이 요청을 처리한 서버 전체의 마지막 수집 상태입니다. 제출·저장·큐 거절·저장 확인 실패·종료 미저장·대기 수를 구분합니다. 개별 요청의 누락 수나 근거 완전성을 뜻하지 않습니다.', 'Last collection status of the server that handled this request. Submitted, stored, queue rejected, write unconfirmed, abandoned and pending counts are separate. These are not missing counts or completeness claims for this request.'],
    'work.collection.NO_GAPS_REPORTED': ['마지막 수집 상태에서 저장 문제는 보고되지 않았습니다. 이것만으로 모든 근거가 수집되었다는 뜻은 아닙니다.', 'No storage issue was reported in the last collection status. This does not establish complete evidence.'],
    'work.collection.GAPS_REPORTED': ['이 서버에서 일부 기록의 저장을 확인하지 못했습니다. 누락된 근거를 성공으로 해석하지 마십시오.', 'Some records on this server could not be confirmed as stored. Missing evidence is not success.'],
    'work.collection.PENDING': ['아직 저장 중인 기록이 있습니다. 잠시 후 다시 확인해 주십시오.', 'Some records are still being saved. Check again shortly.'],
    'work.collection.UNKNOWN': ['수집 상태가 오래되었거나 일부가 없어 확인할 수 없습니다.', 'Collection status is stale or incomplete and cannot be confirmed.'],
    'work.collection.NOT_CAPTURED': ['이 요청에는 서버 수집 상태가 연결되어 있지 않습니다.', 'No server collection status was linked to this request.'],
    'work.collection.UNAVAILABLE': ['현재 수집 상태를 읽을 수 없습니다. 정상으로 판정하지 않습니다.', 'Collection status is currently unavailable. It is not considered healthy.'],
    'work.stream.connecting': ['새 근거 연결 중', 'Connecting to new evidence'],
    'work.stream.connected': ['새 근거를 자동으로 확인하고 있습니다.', 'New evidence is checked automatically.'],
    'work.stream.reconnecting': ['연결을 다시 시도하고 있습니다. 저장된 근거는 유지됩니다.', 'Reconnecting. Previously saved evidence is preserved.'],
    'work.stream.paused': ['화면으로 돌아오면 새 근거를 이어서 확인합니다.', 'New evidence will resume when you return.'],
    'work.stream.unavailable': ['새 근거를 불러오지 못했습니다. 표시된 이전 기록은 유지되며 다시 확인합니다.', 'New evidence could not be loaded. Previous records remain visible while retrying.'],

    "work.projects": [
        "프로젝트",
        "Projects"
    ],
    "work.projects.lead": [
        "맡은 업무에서 시작하세요. 문서를 여는 실제 활동이 보안 판단의 출발점이 됩니다.",
        "Start with your work. Opening a real document begins the runtime security flow."
    ],
    "work.projects.list": [
        "업무 프로젝트",
        "Business projects"
    ],
    "work.assigned": [
        "내 담당",
        "Assigned to me"
    ],
    "work.other": [
        "다른 프로젝트",
        "Other project"
    ],
    "work.documents": [
        "문서",
        "Documents"
    ],
    "work.documents.lead": [
        "필요한 문서를 찾은 뒤, 열람 목적을 선택하세요.",
        "Find a document, then select your reason for opening it."
    ],
    "work.count": [
        "문서 {n}개",
        "Documents: {n}"
    ],
    "work.open": [
        "문서 보기",
        "View documents"
    ],
    "work.search": [
        "문서 검색",
        "Search documents"
    ],
    "work.search.action": [
        "검색",
        "Search"
    ],
    "work.search.hint": [
        "제목과 소개에서 검색합니다.",
        "Search titles and descriptions."
    ],
    "work.empty": [
        "표시할 항목이 없습니다. 검색어를 바꾸거나 이전 화면으로 돌아가세요.",
        "No matching items. Change the search or return to the previous page."
    ],
    "work.document": [
        "문서 열람",
        "Open a document"
    ],
    "work.document.lead": [
        "열람 목적을 선택하면 보호된 업무 경로를 통해 본문을 요청합니다.",
        "Select a purpose to request the content through the protected workflow."
    ],
    "work.purpose": [
        "업무 목적",
        "Purpose of access"
    ],
    "work.purpose.PROJECT_REVIEW": [
        "프로젝트 업무 확인",
        "Project review"
    ],
    "work.purpose.UNDECLARED": [
        "목적을 제시하지 않음",
        "No purpose stated"
    ],
    "work.purpose.CUSTOMER_SUPPORT": [
        "고객 문의 대응",
        "Customer support"
    ],
    "work.purpose.CROSS_PROJECT_REVIEW": [
        "다른 프로젝트 검토",
        "Cross-project review"
    ],
    "work.purpose.note": [
        "선택한 목적은 본인이 입력한 설명입니다. 권한이나 승인을 부여하지 않습니다.",
        "Your selected purpose is a declaration. It does not grant permission or approval."
    ],
    "work.read": [
        "문서 열기",
        "Open document"
    ],
    "work.read.again": [
        "다시 요청",
        "Request again"
    ],
    "work.content": [
        "문서 본문",
        "Document content"
    ],
    "work.closed": [
        "아직 열람하지 않았습니다.",
        "This document has not been opened."
    ],
    "work.sensitivity": [
        "문서 분류",
        "Classification"
    ],
    "work.INTERNAL": [
        "내부 자료",
        "Internal"
    ],
    "work.CONFIDENTIAL": [
        "기밀 자료",
        "Confidential"
    ],
    "work.author": [
        "작성자",
        "Author"
    ],
    "work.updated": [
        "문서 기준일",
        "Document date"
    ],
    "work.version": [
        "문서 버전",
        "Document version"
    ],
    "work.evidence": [
        "요청 근거 보기",
        "View request evidence"
    ],
    "work.request": [
        "요청 근거",
        "Request evidence"
    ],
    "work.request.lead": [
        "업무 응답과 분석·최종 결정을 각각 확인하세요. 뒤늦은 결정이 이미 받은 자료를 되돌리지는 않습니다.",
        "Inspect the business response, analysis and final decision separately. A later decision does not recall content already received."
    ],
    "work.http": [
        "실제 업무 요청",
        "Business request"
    ],
    "work.analysis": [
        "분석 관측",
        "Analysis observations"
    ],
    "work.final": [
        "엔진 최종 결정",
        "Final engine decision"
    ],
    "work.snapshot": [
        "요청 시점 업무 정보",
        "Business facts at request time"
    ],
    "work.no.analysis": [
        "이 요청에 연결된 분석 관측이 아직 없습니다. 미수집 또는 기존 액션 적용 여부를 별도로 확인해야 합니다.",
        "No analysis observations are linked to this request yet. Missing capture or reuse of an existing action requires separate evidence."
    ],
    "work.no.final": [
        "이 요청에 연결된 최종 결정이 아직 없습니다.",
        "No final decision is linked to this request yet."
    ],
    "work.baseline.note": [
        "기본 환경은 같은 정적 권한·업무 규칙을 사용하며 AI 분석을 수행하지 않습니다.",
        "The baseline uses the same static permissions and business rules, without AI analysis."
    ],
    "work.provider.missing": [
        "실제 모델 전송 원문은 아직 수집되지 않았습니다. 분석 콜백을 전송 증거로 표시하지 않습니다.",
        "The actual provider payload has not been captured. Analysis callbacks are not transmission evidence."
    ],
    "work.refresh": [
        "기록 새로고침",
        "Refresh records"
    ],
    "work.status": [
        "HTTP 응답",
        "HTTP response"
    ],
    "work.started": [
        "요청 시작",
        "Request started"
    ],
    "work.finished": [
        "서버 처리 종료",
        "Server processing ended"
    ],
    "work.source": [
        "원본 보기",
        "View source"
    ],
    "work.request.id": [
        "요청 ID",
        "Request ID"
    ],
    "work.success": [
        "문서를 받았습니다. 아래에서 실제 요청의 판단 근거를 확인할 수 있습니다.",
        "Document received. You can inspect the evidence for this request below."
    ],
    "work.failed": [
        "문서를 받지 못했습니다. 응답 상태와 요청 근거를 확인하세요.",
        "The document was not received. Check the response status and request evidence."
    ],
    "work.account": [
        "계정 및 인증 확인",
        "Check account and authentication"
    ],
    "work.reconnect": [
        "업무 환경 연결",
        "Connect to business environments"
    ],
    "work.start": [
        "업무 시작",
        "Start working"
    ],
    "work.environment": [
        "현재 업무 환경",
        "Current environment"
    ],
    "work.loading": [
        "업무 정보를 불러오는 중입니다.",
        "Loading business information."
    ],
    "work.demo": [
        "체험용 업무 자료",
        "Demonstration business data"
    ],
    "work.return": [
        "문서 목록으로",
        "Back to documents"
    ],
    "work.decision.unavailable": [
        "최종 결정 원본 저장소를 읽을 수 없습니다.",
        "The final decision source is unavailable."
    ],
    "work.native.action": [
        "엔진이 반환한 처리",
        "Action returned by the engine"
    ],
    "work.event.CONTEXT_COLLECTED": [
        "요청 문맥 수집",
        "Request context collected"
    ],
    "work.event.LAYER1_START": [
        "1차 분석 시작",
        "Initial analysis started"
    ],
    "work.event.GENERATED_PROMPT": [
        "모델 입력 후보 생성",
        "Model input candidate generated"
    ],
    "work.event.LAYER1_CANDIDATE": [
        "1차 분석 결과",
        "Initial analysis result"
    ],
    "work.event.LAYER2_START": [
        "심화 분석 시작",
        "Further analysis started"
    ],
    "work.event.LAYER2_CANDIDATE": [
        "심화 분석 결과",
        "Further analysis result"
    ],
    "work.event.CANDIDATE_CALLBACK": [
        "결정 후보 전달",
        "Decision candidate reported"
    ],
    "work.event.ANALYSIS_ERROR": [
        "분석 오류",
        "Analysis error"
    ],
    "work.action.ALLOW": [
        "업무 허용",
        "Work allowed"
    ],
    "work.action.CHALLENGE": [
        "추가 확인 요구",
        "Additional verification required"
    ],
    "work.action.BLOCK": [
        "업무 차단",
        "Work blocked"
    ],
    "work.action.ESCALATE": [
        "추가 검토",
        "Further review"
    ],
    "work.action.PENDING_ANALYSIS": [
        "분석 대기",
        "Analysis pending"
    ],
    "work.decision.failed": [
        "분석 실패 후 기록된 처리입니다. 정상적인 모델 판단으로 집계하지 않습니다.",
        "This action was recorded after an analysis failure. It is not a successful model judgment."
    ],
    "work.decision.saved": [
        "엔진 저장소에 기록된 결정입니다. 실제 후속 업무에 적용됐는지는 별도 요청으로 확인합니다.",
        "A decision recorded by the engine. Its effect on subsequent work requires a separate request."
    ],
    "work.prompt.note": [
        "생성 시점의 입력 후보입니다. 실제 공급자 전송과는 구분하며 세션 식별자는 가려서 표시합니다.",
        "This is the generated input candidate, separate from provider transmission. Session identifiers are redacted."
    ],
    "work.failure.type": [
        "원본 오류 구분",
        "Source failure category"
    ],
    "work.mfa.required": [
        "계속하려면 Contexa의 추가 인증을 완료해야 합니다.",
        "Complete Contexa additional verification to continue."
    ],
    "work.mfa.continue": [
        "추가 인증으로 이동",
        "Continue to verification"
    ],
    "work.previous.content": [
        "아래 본문은 이전 열람에서 받은 자료입니다. 현재 요청이 허용됐다는 의미는 아닙니다.",
        "The content below was received earlier. It does not mean the current request was allowed."
    ],
    "work.request.not.sent": [
        "인증 확인 단계에서 중단되어 새 문서 요청은 보내지 않았습니다.",
        "The process stopped at authentication verification. A new document request was not sent."
    ],
    "work.request.network": [
        "요청 결과를 확인하지 못했습니다. 서버 작업이 끝났는지 단정할 수 없습니다.",
        "The request outcome could not be confirmed. The server may still have completed the work."
    ],
    "download.title": [
        "파일 받기",
        "Download a file"
    ],
    "download.lead": [
        "DB에 보관된 문서 버전으로 실제 파일을 만듭니다. 파일 준비와 브라우저 수신을 따로 기록합니다.",
        "Receive a file from the stored document version. File preparation and browser receipt are recorded separately."
    ],
    "download.language": [
        "파일 언어",
        "File language"
    ],
    "download.receive": [
        "파일 받기",
        "Receive file"
    ],
    "download.cancel": [
        "수신 중단",
        "Stop receiving"
    ],
    "download.receiving": [
        "파일을 요청하고 있습니다.",
        "Requesting the file."
    ],
    "download.complete": [
        "파일을 받았고 서버 파일과 해시가 일치합니다. 기기에 저장됐는지는 브라우저 다운로드에서 확인하세요.",
        "File received; its hash matches the server file. Check browser downloads for local saving."
    ],
    "download.mismatch": [
        "받은 자료가 서버 파일 해시와 다릅니다. 파일 저장을 시작하지 않았습니다.",
        "Received content does not match the server hash. File saving was not started."
    ],
    "download.incomplete": [
        "파일을 끝까지 받지 못했습니다. 서버의 파일 준비가 취소됐다는 의미는 아닙니다.",
        "The file was not fully received. The server may still have prepared it."
    ],
    "download.denied": [
        "요청이 제한되어 파일을 받지 못했습니다. 아래 요청 근거에서 확인된 이유와 처리 결과를 확인하세요.",
        "The request was restricted and no file was received. Open the request evidence below for the recorded reason and outcome."
    ],
    "download.not.sent": [
        "요청 준비 단계에서 중단되어 새 파일 요청은 보내지 않았습니다.",
        "Preparation stopped before a new file request was sent."
    ],
    "download.received": [
        "브라우저 수신량",
        "Bytes received by this browser"
    ],
    "download.http": [
        "업무 응답",
        "Business response"
    ],
    "download.file.id": [
        "서버 파일 ID",
        "Server file ID"
    ],
    "download.report.saving": [
        "수신 기록을 저장하고 있습니다. 완료될 때까지 이 화면을 유지해 주세요.",
        "Saving the receipt record. Keep this page open until storage finishes."
    ],
    "download.report.saved": [
        "브라우저 수신 보고를 저장했습니다. 독립적인 수신 인증은 아닙니다.",
        "Browser receipt report saved. This is not independent receipt attestation."
    ],
    "download.report.failed": [
        "수신 보고를 저장하지 못했습니다. 파일 요청을 다시 보내지 않고 보고만 재전송할 수 있습니다.",
        "Receipt report could not be saved. Retry the report without requesting the file again."
    ],
    "download.report.retry": [
        "수신 보고 다시 저장",
        "Retry receipt report"
    ],
    "download.repeat.note": [
        "같은 조건으로 다시 받으면 같은 파일을 사용하며, 보안 확인과 요청 기록은 매번 남습니다.",
        "Repeating the same command reuses the prepared file. Security checks and request records still apply each time."
    ],
    "download.new": [
        "새 요청 준비",
        "Prepare a new request"
    ],
    "download.new.ready": [
        "다음 요청은 새 기록으로 저장됩니다. 이전 결과는 유지됩니다.",
        "The next request will create a new record. Previous results are preserved."
    ],
    "download.return": [
        "문서로 돌아가기",
        "Back to document"
    ],
    "download.measurement": [
        "파일 처리와 수신",
        "File preparation and receipt"
    ],
    "download.prepared": [
        "서버 준비 파일",
        "Prepared server file"
    ],
    "download.written": [
        "서버 응답 출력",
        "Server response output"
    ],
    "download.reported": [
        "브라우저 수신 보고",
        "Browser receipt report"
    ],
    "download.measurement.note": [
        "파일 본문의 크기를 바이트로 표시합니다. 서버 응답 출력은 응답에 쓴 양이며, 실제 수신·기기 저장 완료와 다를 수 있습니다. 미수집 값은 확인되지 않은 상태로 표시합니다.",
        "Values are file-body bytes. Server output measures bytes written to the response; receipt and local saving can differ. Missing values remain unknown."
    ],
    "download.file.reuse": [
        "파일 준비 이력",
        "File preparation history"
    ],
    "download.reused": [
        "같은 명령의 파일 재사용",
        "Reused file from the same command"
    ],
    "download.created": [
        "이 요청에서 파일 생성",
        "File prepared for this request"
    ],
    "download.receipt.unavailable": [
        "수신 보고 저장소를 조회하지 못했습니다.",
        "Receipt reports could not be queried."
    ],
    "download.receipt.source": [
        "브라우저가 보고한 값입니다. 파일과 해시가 일치해도 독립적인 수신 인증은 아닙니다.",
        "Values are reported by the browser. A matching file hash is not independent receipt attestation."
    ],
    "download.receipt.missing": [
        "이 요청의 브라우저 수신 보고가 없습니다. 수신량을 0으로 단정하지 않습니다.",
        "No browser receipt report exists for this request. Received bytes are unknown, not zero."
    ],
    "download.restored": [
        "이전 요청의 수신 기록입니다. 새 파일을 요청하거나 다시 저장한 결과가 아닙니다.",
        "This is the receipt record from the previous request; no new file was requested or saved."
    ],
    "download.interrupted": [
        "화면이 닫히기 전 요청의 완료 여부를 확인하지 못했습니다. 같은 명령으로 다시 요청하면 준비된 파일이 있을 경우 재사용합니다.",
        "The previous request ended without a confirmed result. Retrying the same command reuses its file if it was prepared."
    ],
    "download.storage.failed": [
        "이 탭에 요청 기록을 안전하게 보관할 수 없어 새 요청을 보내지 않았습니다. 기존 계정으로 돌아가거나 새 탭에서 시작해 주세요.",
        "A new request was not sent because this tab cannot retain its request record. Return to the original account or start in a new tab."
    ],
    "download.pending.other": [
        "다른 파일의 수신 기록 저장이 남아 있습니다. 해당 화면에서 먼저 저장해 주세요.",
        "A receipt for another file is awaiting storage. Return to that transfer to save it first."
    ],
    "download.pending.return": [
        "미저장 수신 기록으로 이동",
        "Return to the pending receipt"
    ],
    "customer.list": [
        "고객",
        "Customers"
    ],
    "customer.list.lead": [
        "담당 프로젝트의 고객을 찾고 필요한 업무 정보를 확인하세요.",
        "Find customers in your project and review the information needed for your work."
    ],
    "customer.project.filter": [
        "프로젝트 범위",
        "Project scope"
    ],
    "customer.all.projects": [
        "모든 프로젝트",
        "All projects"
    ],
    "customer.search": [
        "고객 검색",
        "Find customers"
    ],
    "customer.search.hint": [
        "고객 이름 또는 고객 번호로 검색합니다.",
        "Search by customer name or customer ID."
    ],
    "customer.name": [
        "고객 이름",
        "Customer name"
    ],
    "customer.industry": [
        "업종",
        "Industry"
    ],
    "customer.region": [
        "지역",
        "Region"
    ],
    "customer.assignment": [
        "담당 범위",
        "Responsibility"
    ],
    "customer.open": [
        "상세 보기",
        "View details"
    ],
    "customer.count": [
        "{n}개 고객",
        "{n} customers"
    ],
    "customer.demo.note": [
        "이 목록은 체험용 가상 고객 데이터입니다. 연락처와 활동 내역은 상세 열람 후 제공됩니다.",
        "These are fictional demonstration customers. Contact and activity records are provided after opening their details."
    ],
    "customer.detail": [
        "고객 상세",
        "Customer details"
    ],
    "customer.detail.lead": [
        "업무 목적을 확인하고 연락처와 활동 내역을 열람합니다.",
        "Confirm your purpose to view contact details and activity history."
    ],
    "customer.protected": [
        "연락처와 활동 내역",
        "Contact and activity records"
    ],
    "customer.closed": [
        "열람을 요청하면 이 고객의 연락처와 활동 내역을 확인할 수 있습니다.",
        "Request access to view this customer’s contact and activity records."
    ],
    "customer.activity": [
        "활동 내역",
        "Activity history"
    ],
    "customer.contact": [
        "고객 담당자",
        "Customer contact"
    ],
    "customer.email": [
        "업무 이메일",
        "Business email"
    ],
    "customer.plan": [
        "서비스 계획",
        "Service plan"
    ],
    "customer.return": [
        "고객 목록으로",
        "Back to customers"
    ],
    "approval.list": [
        "업무 승인",
        "Work approvals"
    ],
    "approval.new": [
        "승인 신청",
        "Request approval"
    ],
    "approval.lead": [
        "자료의 대상·목적·기간을 정하고 실제 검토 이력을 확인합니다.",
        "Define the scope, purpose and duration, then follow the review record."
    ],
    "approval.list.note": [
        "이 체험 공간의 최근 신청을 최대 100건 표시합니다. 검토 권한이 있으면 다른 업무 계정의 신청도 볼 수 있습니다.",
        "Shows up to 100 recent requests in this workspace. Reviewers can also see requests from its other business accounts."
    ],
    "approval.request.title": [
        "새 업무 승인 신청",
        "Request work approval"
    ],
    "approval.resource.type": [
        "자료 종류",
        "Resource type"
    ],
    "approval.targets": [
        "승인 대상",
        "Requested scope"
    ],
    "approval.targets.note": [
        "선택한 자료의 현재 버전을 승인 대상에 고정합니다.",
        "The current version of each selected resource is fixed in this request."
    ],
    "approval.purpose.PROJECT_REVIEW": [
        "프로젝트 검토",
        "Project review"
    ],
    "approval.purpose.CUSTOMER_SUPPORT": [
        "고객 지원",
        "Customer support"
    ],
    "approval.purpose.APPROVED_BULK_DELIVERY": [
        "자료 묶음 전달",
        "Bulk delivery"
    ],
    "approval.purpose.EMERGENCY_MAINTENANCE": [
        "긴급 운영 지원",
        "Emergency operations"
    ],
    "approval.validity": [
        "신청 시점부터 유효 기간",
        "Valid period from request time"
    ],
    "approval.validity.one": [
        "1분",
        "1 minute"
    ],
    "approval.validity.five": [
        "5분",
        "5 minutes"
    ],
    "approval.validity.fifteen": [
        "15분",
        "15 minutes"
    ],
    "approval.validity.thirty": [
        "30분",
        "30 minutes"
    ],
    "approval.reason": [
        "신청 이유",
        "Request reason"
    ],
    "approval.reason.note": [
        "신청자가 작성한 설명입니다. 검토자가 승인하기 전에는 승인 근거가 되지 않습니다.",
        "This is the requester’s explanation. It is not approval evidence until reviewed."
    ],
    "approval.retry.note": [
        "같은 입력의 재전송은 같은 신청으로 처리됩니다. 새 신청은 목록의 승인 신청에서 시작하세요.",
        "Resending identical input keeps the same request. Start a new request from the approval list."
    ],
    "approval.submit": [
        "신청 보내기",
        "Submit request"
    ],
    "approval.return": [
        "승인 목록으로",
        "Back to approvals"
    ],
    "approval.detail": [
        "신청 상세",
        "Approval request"
    ],
    "approval.history": [
        "신청과 검토 이력",
        "Request and review history"
    ],
    "approval.business.note": [
        "이 승인은 정해진 업무 범위에 대한 검토 기록입니다. 로그인 권한·추가 인증·보안 제한을 변경하지 않습니다.",
        "This records a review of the specified work scope. It does not change login permissions, additional authentication or security restrictions."
    ],
    "approval.expiry.note": [
        "저장된 유효기간이 지났습니다. 이전 승인·거절 기록은 그대로 보존됩니다.",
        "The recorded validity period has ended. Previous request and review records remain unchanged."
    ],
    "approval.review": [
        "신청 검토",
        "Review request"
    ],
    "approval.review.note": [
        "담당 범위의 검토 권한이 있는 다른 계정으로만 승인·거절할 수 있습니다. 처리 후 기존 결정을 덮어쓸 수 없습니다.",
        "Only another account with review authority for this scope can approve or reject it. A recorded decision cannot be overwritten."
    ],
    "approval.verdict": [
        "검토 결과",
        "Decision"
    ],
    "approval.approve": [
        "승인",
        "Approve"
    ],
    "approval.reject": [
        "거절",
        "Reject"
    ],
    "approval.review.reason": [
        "검토 이유",
        "Review reason"
    ],
    "approval.review.submit": [
        "검토 결과 저장",
        "Save decision"
    ],
    "approval.review.saved": [
        "검토 결과와 이력을 저장했습니다.",
        "Decision and review history saved."
    ],
    "approval.empty": [
        "아직 신청한 업무 승인이 없습니다.",
        "No work approval requests yet."
    ],
    "approval.target.count": [
        "대상 {n}개",
        "{n} resources"
    ],
    "approval.selected.count": [
        "{n}개 선택",
        "{n} selected"
    ],
    "approval.select.required": [
        "승인 대상을 하나 이상 선택해 주세요.",
        "Select at least one resource."
    ],
    "approval.status.PENDING": [
        "검토 대기",
        "Awaiting review"
    ],
    "approval.status.APPROVED": [
        "승인됨",
        "Approved"
    ],
    "approval.status.REJECTED": [
        "거절됨",
        "Rejected"
    ],
    "approval.status.EXPIRED": [
        "기간 만료",
        "Expired"
    ],
    "approval.requester": [
        "신청자",
        "Requester"
    ],
    "approval.requested": [
        "신청 시각",
        "Requested at"
    ],
    "approval.expires": [
        "유효 기한",
        "Valid until"
    ],
    "approval.submitted": [
        "신청 접수",
        "Request submitted"
    ],
    "approval.error.400": [
        "입력과 선택한 대상을 확인해 주세요.",
        "Check your input and selected resources."
    ],
    "approval.error.403": [
        "현재 계정에 이 범위를 검토할 권한이 없거나 자기 신청입니다. 계정과 담당 범위를 확인해 주세요.",
        "This account cannot review this scope or its own request. Check the account and assigned projects."
    ],
    "approval.error.404": [
        "이 체험 공간에서 해당 신청이나 자료를 찾을 수 없습니다.",
        "The request or resource was not found in this workspace."
    ],
    "approval.error.409": [
        "이미 처리됐거나 유효기간 또는 명령 입력이 달라졌습니다. 최신 기록을 확인해 주세요.",
        "The request was already processed, expired, or the command input changed. Refresh the record."
    ],
    "approval.link.label": [
        "업무 승인",
        "Work approval"
    ],
    "approval.link.none": [
        "승인 연결 없음",
        "No approval linked"
    ],
    "approval.link.note": [
        "필요한 경우 검토가 끝난 승인을 연결하세요.",
        "Link a reviewed approval when relevant."
    ],
    "approval.link.required": [
        "이 업무 목적은 유효한 승인이 필요합니다.",
        "This work purpose requires a valid approval."
    ],
    "approval.link.unavailable": [
        "승인 목록을 불러오지 못했습니다. 화면을 새로고침해 주세요.",
        "The approval list is unavailable. Refresh this page."
    ],
    "approval.work.rejected": [
        "업무 승인을 확인할 수 없어 요청을 처리하지 않았습니다.",
        "The work request was not processed because its approval could not be validated."
    ],
    "approval.status.NOT_LINKED": [
        "요청에 승인 연결 없음",
        "No approval linked to this request"
    ],
    "approval.status.UNAVAILABLE": [
        "이 계정에서 확인할 수 없는 승인",
        "Approval unavailable to this account"
    ],
    "approval.status.PURPOSE_MISMATCH": [
        "승인 목적과 요청 목적이 다름",
        "Approval purpose does not match"
    ],
    "approval.status.SCOPE_MISMATCH": [
        "승인 대상 또는 버전이 다름",
        "Approval resource or version does not match"
    ],
    "approval.observed": [
        "서버 확인 시각",
        "Checked by server at"
    ],
    "approval.evidence": [
        "요청 시점의 업무 승인",
        "Work approval at request time"
    ],
    "approval.evidence.note": [
        "요청 시점에 확인한 업무 승인입니다. 이후의 만료·보안 판단과 구분합니다.",
        "This is the work approval observed when the request began, separate from later expiry or security decisions."
    ],
    "approval.reference": [
        "승인 기록 번호",
        "Approval record ID"
    ],
    "approval.reviewer": [
        "검토자",
        "Reviewer"
    ],
    "approval.selection.unavailable": [
        "선택한 자료 일부를 확인할 수 없습니다. 자료 종류와 프로젝트를 다시 선택해 대상을 확인하세요.",
        "Some selected resources are unavailable. Choose the resource type and project again to review the targets."
    ],
    "approval.export.return": [
        "이 자료의 내보내기 준비",
        "Prepare to export these resources"
    ],
    "approval.return.approved": [
        "대상과 승인을 연결합니다. 실제 요청 시 유효성과 보안 상태를 다시 확인합니다.",
        "The resources and approval will be linked. Validity and security state are checked again when you request the file."
    ],
    "approval.return.notApproved": [
        "현재 유효한 승인 상태가 아닙니다. 이동만으로 업무가 허용되지는 않습니다.",
        "This approval is not currently valid. Returning to the task does not grant access."
    ],
    "export.setup": ["목적과 승인 확인", "Review purpose and approval"],
    "export.document.count": ["문서 {n}개", "Documents: {n}"],
    "export.customer.count": ["고객 자료 {n}개", "Customer records: {n}"],
    "export.runtime.note": [
        "파일 받기를 누를 때 실제 업무 요청을 보냅니다. Contexa 환경에서는 이 요청의 문맥도 분석 대상이 됩니다.",
        "The business request is sent when you receive the file. In the Contexa environment, its context is also subject to analysis."
    ],
    "export.retry.help": ["다시 받기와 수신 기록 안내", "About retries and receipt records"],
    "export.title": [
        "선택 자료 내보내기",
        "Export selected resources"
    ],
    "export.lead": [
        "대상과 목적을 확인하고 실제 파일을 받습니다.",
        "Review the selected resources and purpose, then receive the actual file."
    ],
    "export.targets": [
        "내보낼 자료",
        "Resources to export"
    ],
    "export.prepared.items": [
        "서버 파일에 포함된 업무 항목",
        "Business items in the server file"
    ],
    "export.zip.note": [
        "문서 {n}개의 본문과 파일 목록을 ZIP 파일로 받습니다.",
        "Receive {n} document bodies and their file manifest as a ZIP archive."
    ],
    "export.csv.note": [
        "고객 {n}명의 버전·연락처·업무 정보를 CSV 파일로 받습니다.",
        "Receive version, contact and service information for {n} customers as CSV."
    ],
    "export.back": [
        "목록으로 돌아가기",
        "Back to list"
    ],
    "export.select": [
        "자료 선택",
        "Select resource"
    ],
    "export.select.visible": [
        "현재 목록 전체 선택",
        "Select current list"
    ],
    "export.clear": [
        "선택 해제",
        "Clear selection"
    ],
    "export.action": [
        "선택 자료 내보내기",
        "Export selected"
    ],
    "export.selected.count": [
        "{n}개 선택",
        "{n} selected"
    ],
    "export.limit": [
        "한 번에 최대 50개를 선택할 수 있습니다.",
        "Select up to 50 resources per export."
    ],
    "export.selection.invalid": [
        "목록에서 내보낼 자료를 다시 선택해 주세요.",
        "Return to the list and select the resources to export."
    ],
    "export.selection.storage": [
        "선택 내용을 이 탭에 보관하지 못했습니다. 새로고침하면 다시 선택해야 합니다.",
        "Selection could not be saved in this tab. Select it again after a refresh."
    ],
    "download.owner.changed": [
        "이 탭에 다른 계정의 진행 중 요청 또는 미저장 수신 기록이 있습니다. 원래 계정으로 돌아가 기록을 확인해 주세요.",
        "This tab has an unfinished transfer or unsaved receipt for another account. Return to that account to review it."
    ],
    "export.target.summary": [
        "선택한 자료 {n}개 확인",
        "Review {n} selected resources"
    ],
    "download.technical": [
        "전송 상세 보기",
        "View transfer details"
    ]
};
