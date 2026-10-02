CREATE TABLE lab.business_project (
    id varchar(40) PRIMARY KEY,
    code varchar(20) NOT NULL UNIQUE,
    title_ko text NOT NULL,
    title_en text NOT NULL,
    summary_ko text NOT NULL,
    summary_en text NOT NULL,
    department varchar(80) NOT NULL
);
CREATE TABLE lab.project_assignment (
    project_id varchar(40) NOT NULL REFERENCES lab.business_project(id),
    username varchar(80) NOT NULL,
    responsibility varchar(120) NOT NULL,
    PRIMARY KEY (project_id, username)
);
CREATE TABLE lab.business_document (
    id varchar(60) NOT NULL,
    version integer NOT NULL CHECK (version > 0),
    project_id varchar(40) NOT NULL REFERENCES lab.business_project(id),
    title_ko text NOT NULL,
    title_en text NOT NULL,
    summary_ko text NOT NULL,
    summary_en text NOT NULL,
    body_ko text NOT NULL,
    body_en text NOT NULL,
    sensitivity varchar(30) NOT NULL,
    author_name varchar(100) NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (id, version)
);
CREATE TRIGGER immutable_business_document BEFORE UPDATE ON lab.business_document
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
CREATE TABLE lab.business_request_snapshot (
    request_id uuid PRIMARY KEY,
    visitor_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    username varchar(80) NOT NULL,
    document_id varchar(60) NOT NULL,
    document_version integer NOT NULL,
    observed_at timestamptz NOT NULL,
    snapshot jsonb NOT NULL,
    content_sha256 char(64) NOT NULL,
    FOREIGN KEY (document_id, document_version) REFERENCES lab.business_document(id, version)
);
CREATE INDEX business_request_owner ON lab.business_request_snapshot (visitor_id, observed_at DESC);
CREATE TRIGGER immutable_business_request BEFORE UPDATE ON lab.business_request_snapshot
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
CREATE TABLE lab.business_document_read (
    request_id uuid PRIMARY KEY REFERENCES lab.business_request_snapshot(request_id),
    document_id varchar(60) NOT NULL,
    document_version integer NOT NULL,
    content_sha256 char(64) NOT NULL,
    content_bytes integer NOT NULL CHECK (content_bytes >= 0),
    completed_at timestamptz NOT NULL,
    FOREIGN KEY (document_id, document_version) REFERENCES lab.business_document(id, version)
);
CREATE TABLE lab.business_http_observation (
    request_id uuid PRIMARY KEY,
    visitor_id uuid,
    method varchar(12) NOT NULL,
    path text NOT NULL,
    started_at timestamptz NOT NULL,
    completed_at timestamptz NOT NULL,
    http_status integer,
    failure_type varchar(100)
);
CREATE TRIGGER immutable_business_http BEFORE UPDATE ON lab.business_http_observation
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
INSERT INTO lab.business_project VALUES
('atlas','ATL-26','아틀라스 서비스 개편','Atlas service renewal','고객 포털의 서비스 품질을 개선하는 프로젝트입니다.','A project to improve the customer service portal.','Product Operations'),
('harbor','HBR-26','하버 파트너 정산','Harbor partner settlement','파트너 계약과 정산 절차를 관리합니다.','Partner contracts and settlement operations.','Finance'),
('summit','SMT-26','서밋 출시 준비','Summit launch readiness','새 서비스의 출시 일정과 영업 계획을 준비합니다.','Launch schedule and commercial preparation.','Commercial');
INSERT INTO lab.project_assignment VALUES
('atlas','user','Service operations'),('atlas','admin','Project review'),('harbor','admin','Settlement review');
INSERT INTO lab.business_document VALUES ('atlas-service-plan', 1, 'atlas', '서비스 운영 계획', 'Service operations plan', '담당자와 월간 운영 업무를 확인합니다.', 'Responsibilities and monthly operations.', '서비스 운영 계획

1. 업무 범위
고객 포털의 운영 담당자는 문의 분류와 서비스 안내 문서를 주 단위로 검토합니다. 담당 프로젝트는 아틀라스입니다.

2. 운영 절차
매주 월요일 문의 현황을 검토하고 개선 항목을 기록합니다. 변경 사항은 프로젝트 담당자의 검토 후 배포합니다.

3. 완료 기준
운영 체크리스트와 변경 이력이 함께 남아 있어야 합니다. 이 문서는 Runtime Lab 체험용 업무 자료입니다.', 'Service operations plan

1. Scope
The Atlas operations team reviews customer enquiries and service guidance weekly.

2. Procedure
Review the enquiry backlog each Monday. Record improvements and obtain project review before release.

3. Completion
Retain both the operations checklist and change history. This is a Runtime Lab demonstration business document.', 'INTERNAL', 'Contexa Lab Team', '2026-09-01T09:00:00Z');
INSERT INTO lab.business_document VALUES ('atlas-release-checklist', 1, 'atlas', '배포 점검표', 'Release checklist', '배포 전 확인할 운영 항목입니다.', 'Operational checks before release.', '배포 점검표

담당: 아틀라스 운영팀
서비스 안내 최신화, 장애 연락망 확인, 변경 내용 검토, 배포 후 상태 확인을 순서대로 진행합니다.
점검 결과와 검토자를 변경 이력에 남깁니다.', 'Release checklist

Owner: Atlas operations
Update guidance, verify the incident contact list, review changes, and inspect service health after release. Retain the review record.', 'INTERNAL', 'Contexa Lab Team', '2026-09-01T09:00:00Z');
INSERT INTO lab.business_document VALUES ('atlas-support-guide', 1, 'atlas', '고객 지원 안내', 'Customer support guide', '문의 분류와 담당자 연결 절차입니다.', 'Enquiry routing and ownership.', '고객 지원 안내

일반 문의는 운영팀에서 처리하고 계약 문의는 담당 영업 부서로 연결합니다. 고객의 비밀번호나 인증 코드를 문의 내용에 남기지 않습니다.', 'Customer support guide

Operations handles general enquiries; commercial owners handle contract questions. Never include customer passwords or verification codes in support notes.', 'INTERNAL', 'Contexa Lab Team', '2026-09-01T09:00:00Z');
INSERT INTO lab.business_document VALUES ('harbor-settlement', 1, 'harbor', '파트너 정산 기준', 'Partner settlement terms', '재무 부서가 관리하는 정산 기준입니다.', 'Settlement terms owned by Finance.', '파트너 정산 기준

정산 주기: 월 단위
계약별 정산 근거와 검토 이력을 함께 보관합니다. 외부 제공은 승인된 목적과 대상 범위에 한정합니다.
본 자료는 체험용이며 실제 거래를 포함하지 않습니다.', 'Partner settlement terms

Monthly settlement requires supporting contract records and review history. External disclosure is limited to approved purposes and scope. Demonstration data; no real transactions.', 'CONFIDENTIAL', 'Contexa Lab Team', '2026-09-01T09:00:00Z');
INSERT INTO lab.business_document VALUES ('harbor-review', 1, 'harbor', '분기 정산 검토', 'Quarterly settlement review', '정산 자료의 검토 순서를 정리합니다.', 'Review sequence for settlement records.', '분기 정산 검토

재무 담당자는 계약 변경 내역과 정산 내역을 대조합니다. 차이가 있으면 원인을 기록하고 검토자에게 전달합니다.', 'Quarterly settlement review

Finance compares contract changes with settlement records, documents discrepancies, and routes them for review.', 'CONFIDENTIAL', 'Contexa Lab Team', '2026-09-01T09:00:00Z');
INSERT INTO lab.business_document VALUES ('summit-launch', 1, 'summit', '출시 준비 보고', 'Launch readiness brief', '출시 전 검토가 필요한 내부 계획입니다.', 'Internal planning for launch review.', '출시 준비 보고

영업 계획과 출시 일정을 담당 부서에서 검토합니다. 공유 대상은 프로젝트 협업 범위에 따릅니다. 외부 발표 전까지 내부 자료로 관리합니다.', 'Launch readiness brief

The commercial team reviews the launch schedule and sales plan. Sharing follows the project collaboration scope; retain internally until public announcement.', 'CONFIDENTIAL', 'Contexa Lab Team', '2026-09-01T09:00:00Z');
