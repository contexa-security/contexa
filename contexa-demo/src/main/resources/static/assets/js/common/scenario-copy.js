export const scenarioCopy = {
    S01: ['평소 업무가 원활하게 이어지는지 확인합니다.', 'Check that routine work continues smoothly.'],
    S02: ['처리량이 많아도 실제 승인과 범위가 있으면 정당한 업무일 수 있습니다.', 'High volume can be legitimate when the scope and approval are valid.'],
    S03: ['평소와 다른 업무라도 유효한 예외 승인이 판단 근거가 되는지 확인합니다.', 'Check whether a valid exception approval informs the decision on unusual work.'],
    S04: ['정상 로그인 이후 담당하지 않는 자료를 연속해서 찾는 상황입니다.', 'A signed-in account explores unrelated materials in sequence.'],
    S05: ['접근할 수 있는 권한과 지금 처리할 정당한 업무 범위의 차이를 확인합니다.', 'Explore the difference between permission to access data and a legitimate reason to use it.'],
    S06: ['한 번의 요청보다 낮은 속도로 누적되는 활동의 흐름을 확인합니다.', 'Explore activity that accumulates gradually rather than in one large request.'],
    S07: ['긴급하다는 주장만 있고 확인된 승인이 없을 때의 판단을 확인합니다.', 'Explore a claim of urgency without a verified approval.'],
    S08: ['이력이 부족한 사용자에 대해 없는 근거를 추측하지 않는지 확인합니다.', 'Check how the system handles a user with little history without inventing evidence.'],
    S09: ['문서 내용이 보안 지시나 승인 원본으로 잘못 취급되지 않는지 확인합니다.', 'Check that document content is not mistaken for a security instruction or an approval record.']
};

export const operationCopy = {
    LIST_PROJECTS: ['프로젝트 목록 확인', 'Browse projects'],
    READ_DOCUMENTS: ['문서 열람', 'Read documents'],
    EXPORT_DOCUMENTS: ['문서 내보내기', 'Export documents'],
    READ_APPROVAL: ['실제 승인 확인', 'Check the actual approval'],
    READ_CUSTOMERS: ['고객 자료 열람', 'Read customer records'],
    EXPORT_CUSTOMERS: ['고객 자료 내보내기', 'Export customer records']
};

export const selectorCopy = {
    ASSIGNED_PROJECTS: ['담당 프로젝트', 'Assigned projects'],
    ASSIGNED_PROJECT_DOCUMENTS: ['담당 프로젝트의 자료', 'Assigned project documents'],
    VALID_BULK_APPROVAL: ['범위와 기간이 유효한 대량 처리 승인', 'Valid approval for bulk work'],
    APPROVED_PROJECT_DOCUMENTS: ['실제 승인 범위의 자료', 'Documents within the approved scope'],
    VALID_EMERGENCY_APPROVAL: ['유효한 긴급 업무 승인', 'Valid emergency approval'],
    EXCEPTION_APPROVED_DOCUMENTS: ['예외 승인이 적용된 자료', 'Documents covered by the exception'],
    VISIBLE_PROJECTS: ['권한으로 조회할 수 있는 프로젝트', 'Projects visible with the current permissions'],
    UNASSIGNED_PROJECT_DOCUMENTS: ['담당하지 않는 프로젝트의 자료', 'Documents outside assigned projects'],
    UNASSIGNED_CUSTOMER_SCOPE: ['담당 범위 밖의 고객 자료', 'Customer records outside assigned scope'],
    PREVIOUSLY_READ_UNASSIGNED_DOCUMENTS: ['이전에 읽은 담당 범위 밖의 자료', 'Previously read documents outside assigned scope'],
    DOCUMENT_WITH_UNTRUSTED_INSTRUCTION: ['보안 판단을 유도하는 내용이 포함된 문서', 'A document containing an attempt to influence the security decision']
};
