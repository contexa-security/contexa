CREATE TABLE lab.business_customer (
    id varchar(60) NOT NULL,
    version integer NOT NULL CHECK (version > 0),
    project_id varchar(40) NOT NULL REFERENCES lab.business_project(id),
    name_ko text NOT NULL,
    name_en text NOT NULL,
    industry_ko text NOT NULL,
    industry_en text NOT NULL,
    region_ko text NOT NULL,
    region_en text NOT NULL,
    sensitivity varchar(30) NOT NULL,
    contact_name text NOT NULL,
    contact_email text NOT NULL,
    service_plan_ko text NOT NULL,
    service_plan_en text NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (id,version)
);
CREATE TRIGGER immutable_business_customer BEFORE UPDATE ON lab.business_customer
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
CREATE TABLE lab.customer_activity (
    id varchar(80) PRIMARY KEY,
    customer_id varchar(60) NOT NULL,
    customer_version integer NOT NULL,
    occurred_at timestamptz NOT NULL,
    title_ko text NOT NULL,
    title_en text NOT NULL,
    note_ko text NOT NULL,
    note_en text NOT NULL,
    FOREIGN KEY (customer_id,customer_version) REFERENCES lab.business_customer(id,version)
);
CREATE TRIGGER immutable_customer_activity BEFORE UPDATE ON lab.customer_activity
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
ALTER TABLE lab.business_request_snapshot
    ALTER COLUMN document_id DROP NOT NULL,
    ALTER COLUMN document_version DROP NOT NULL,
    ADD COLUMN resource_type varchar(20) NOT NULL DEFAULT 'DOCUMENT',
    ADD COLUMN customer_id varchar(60),
    ADD COLUMN customer_version integer,
    ADD FOREIGN KEY (customer_id,customer_version) REFERENCES lab.business_customer(id,version),
    ADD CONSTRAINT business_request_target CHECK (
        (resource_type='DOCUMENT' AND document_id IS NOT NULL AND document_version IS NOT NULL
            AND customer_id IS NULL AND customer_version IS NULL)
        OR (resource_type='CUSTOMER' AND customer_id IS NOT NULL AND customer_version IS NOT NULL
            AND document_id IS NULL AND document_version IS NULL));
CREATE TABLE lab.business_customer_read (
    request_id uuid PRIMARY KEY REFERENCES lab.business_request_snapshot(request_id),
    customer_id varchar(60) NOT NULL,
    customer_version integer NOT NULL,
    content_sha256 char(64) NOT NULL,
    content_bytes integer NOT NULL CHECK (content_bytes >= 0),
    completed_at timestamptz NOT NULL,
    FOREIGN KEY (customer_id,customer_version) REFERENCES lab.business_customer(id,version)
);
CREATE TRIGGER immutable_customer_read BEFORE UPDATE ON lab.business_customer_read
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
INSERT INTO lab.business_customer VALUES ('customer-atlas-001','1','atlas','누리 리테일 Atlas','Nuri Retail Atlas','유통','Retail','서울','Seoul','CONFIDENTIAL','Demo Contact 01','customer-atlas-001@customer.example','월간 서비스 점검 및 운영 지원. 체험용 고객 데이터입니다.','Monthly service review and operational support. Fictional demonstration customer.','2026-09-01T09:00:00Z');
INSERT INTO lab.customer_activity VALUES ('customer-atlas-001-1','customer-atlas-001','1','2026-09-01T09:00:00Z','서비스 시작','Service onboarding','고객 포털 이용 절차를 안내했습니다.','Reviewed the customer portal onboarding process.');
INSERT INTO lab.customer_activity VALUES ('customer-atlas-001-2','customer-atlas-001','1','2026-09-02T09:00:00Z','운영 점검','Operations review','월간 운영 현황과 다음 점검 일정을 확인했습니다.','Reviewed monthly operations and the next service review.');
INSERT INTO lab.business_customer VALUES ('customer-atlas-002','1','atlas','온길 물류 Atlas','Ongil Logistics Atlas','물류','Logistics','부산','Busan','CONFIDENTIAL','Demo Contact 02','customer-atlas-002@customer.example','월간 서비스 점검 및 운영 지원. 체험용 고객 데이터입니다.','Monthly service review and operational support. Fictional demonstration customer.','2026-09-01T09:00:00Z');
INSERT INTO lab.customer_activity VALUES ('customer-atlas-002-1','customer-atlas-002','1','2026-09-01T09:00:00Z','서비스 시작','Service onboarding','고객 포털 이용 절차를 안내했습니다.','Reviewed the customer portal onboarding process.');
INSERT INTO lab.customer_activity VALUES ('customer-atlas-002-2','customer-atlas-002','1','2026-09-02T09:00:00Z','운영 점검','Operations review','월간 운영 현황과 다음 점검 일정을 확인했습니다.','Reviewed monthly operations and the next service review.');
INSERT INTO lab.business_customer VALUES ('customer-atlas-003','1','atlas','다온 스튜디오 Atlas','Daon Studio Atlas','디자인','Design','서울','Seoul','CONFIDENTIAL','Demo Contact 03','customer-atlas-003@customer.example','월간 서비스 점검 및 운영 지원. 체험용 고객 데이터입니다.','Monthly service review and operational support. Fictional demonstration customer.','2026-09-01T09:00:00Z');
INSERT INTO lab.customer_activity VALUES ('customer-atlas-003-1','customer-atlas-003','1','2026-09-01T09:00:00Z','서비스 시작','Service onboarding','고객 포털 이용 절차를 안내했습니다.','Reviewed the customer portal onboarding process.');
INSERT INTO lab.customer_activity VALUES ('customer-atlas-003-2','customer-atlas-003','1','2026-09-02T09:00:00Z','운영 점검','Operations review','월간 운영 현황과 다음 점검 일정을 확인했습니다.','Reviewed monthly operations and the next service review.');
INSERT INTO lab.business_customer VALUES ('customer-atlas-004','1','atlas','마루 교육 Atlas','Maru Learning Atlas','교육','Education','부산','Busan','CONFIDENTIAL','Demo Contact 04','customer-atlas-004@customer.example','월간 서비스 점검 및 운영 지원. 체험용 고객 데이터입니다.','Monthly service review and operational support. Fictional demonstration customer.','2026-09-01T09:00:00Z');
INSERT INTO lab.customer_activity VALUES ('customer-atlas-004-1','customer-atlas-004','1','2026-09-01T09:00:00Z','서비스 시작','Service onboarding','고객 포털 이용 절차를 안내했습니다.','Reviewed the customer portal onboarding process.');
INSERT INTO lab.customer_activity VALUES ('customer-atlas-004-2','customer-atlas-004','1','2026-09-02T09:00:00Z','운영 점검','Operations review','월간 운영 현황과 다음 점검 일정을 확인했습니다.','Reviewed monthly operations and the next service review.');
INSERT INTO lab.business_customer VALUES ('customer-atlas-005','1','atlas','푸른 제조 Atlas','Pureun Manufacturing Atlas','제조','Manufacturing','서울','Seoul','CONFIDENTIAL','Demo Contact 05','customer-atlas-005@customer.example','월간 서비스 점검 및 운영 지원. 체험용 고객 데이터입니다.','Monthly service review and operational support. Fictional demonstration customer.','2026-09-01T09:00:00Z');
INSERT INTO lab.customer_activity VALUES ('customer-atlas-005-1','customer-atlas-005','1','2026-09-01T09:00:00Z','서비스 시작','Service onboarding','고객 포털 이용 절차를 안내했습니다.','Reviewed the customer portal onboarding process.');
INSERT INTO lab.customer_activity VALUES ('customer-atlas-005-2','customer-atlas-005','1','2026-09-02T09:00:00Z','운영 점검','Operations review','월간 운영 현황과 다음 점검 일정을 확인했습니다.','Reviewed monthly operations and the next service review.');
INSERT INTO lab.business_customer VALUES ('customer-atlas-006','1','atlas','모아 서비스 Atlas','Moa Services Atlas','서비스','Services','부산','Busan','CONFIDENTIAL','Demo Contact 06','customer-atlas-006@customer.example','월간 서비스 점검 및 운영 지원. 체험용 고객 데이터입니다.','Monthly service review and operational support. Fictional demonstration customer.','2026-09-01T09:00:00Z');
INSERT INTO lab.customer_activity VALUES ('customer-atlas-006-1','customer-atlas-006','1','2026-09-01T09:00:00Z','서비스 시작','Service onboarding','고객 포털 이용 절차를 안내했습니다.','Reviewed the customer portal onboarding process.');
INSERT INTO lab.customer_activity VALUES ('customer-atlas-006-2','customer-atlas-006','1','2026-09-02T09:00:00Z','운영 점검','Operations review','월간 운영 현황과 다음 점검 일정을 확인했습니다.','Reviewed monthly operations and the next service review.');
INSERT INTO lab.business_customer VALUES ('customer-harbor-001','1','harbor','누리 리테일 Harbor','Nuri Retail Harbor','유통','Retail','서울','Seoul','CONFIDENTIAL','Demo Contact 01','customer-harbor-001@customer.example','월간 서비스 점검 및 운영 지원. 체험용 고객 데이터입니다.','Monthly service review and operational support. Fictional demonstration customer.','2026-09-01T09:00:00Z');
INSERT INTO lab.customer_activity VALUES ('customer-harbor-001-1','customer-harbor-001','1','2026-09-01T09:00:00Z','서비스 시작','Service onboarding','고객 포털 이용 절차를 안내했습니다.','Reviewed the customer portal onboarding process.');
INSERT INTO lab.customer_activity VALUES ('customer-harbor-001-2','customer-harbor-001','1','2026-09-02T09:00:00Z','운영 점검','Operations review','월간 운영 현황과 다음 점검 일정을 확인했습니다.','Reviewed monthly operations and the next service review.');
INSERT INTO lab.business_customer VALUES ('customer-harbor-002','1','harbor','온길 물류 Harbor','Ongil Logistics Harbor','물류','Logistics','부산','Busan','CONFIDENTIAL','Demo Contact 02','customer-harbor-002@customer.example','월간 서비스 점검 및 운영 지원. 체험용 고객 데이터입니다.','Monthly service review and operational support. Fictional demonstration customer.','2026-09-01T09:00:00Z');
INSERT INTO lab.customer_activity VALUES ('customer-harbor-002-1','customer-harbor-002','1','2026-09-01T09:00:00Z','서비스 시작','Service onboarding','고객 포털 이용 절차를 안내했습니다.','Reviewed the customer portal onboarding process.');
INSERT INTO lab.customer_activity VALUES ('customer-harbor-002-2','customer-harbor-002','1','2026-09-02T09:00:00Z','운영 점검','Operations review','월간 운영 현황과 다음 점검 일정을 확인했습니다.','Reviewed monthly operations and the next service review.');
INSERT INTO lab.business_customer VALUES ('customer-harbor-003','1','harbor','다온 스튜디오 Harbor','Daon Studio Harbor','디자인','Design','서울','Seoul','CONFIDENTIAL','Demo Contact 03','customer-harbor-003@customer.example','월간 서비스 점검 및 운영 지원. 체험용 고객 데이터입니다.','Monthly service review and operational support. Fictional demonstration customer.','2026-09-01T09:00:00Z');
INSERT INTO lab.customer_activity VALUES ('customer-harbor-003-1','customer-harbor-003','1','2026-09-01T09:00:00Z','서비스 시작','Service onboarding','고객 포털 이용 절차를 안내했습니다.','Reviewed the customer portal onboarding process.');
INSERT INTO lab.customer_activity VALUES ('customer-harbor-003-2','customer-harbor-003','1','2026-09-02T09:00:00Z','운영 점검','Operations review','월간 운영 현황과 다음 점검 일정을 확인했습니다.','Reviewed monthly operations and the next service review.');
INSERT INTO lab.business_customer VALUES ('customer-harbor-004','1','harbor','마루 교육 Harbor','Maru Learning Harbor','교육','Education','부산','Busan','CONFIDENTIAL','Demo Contact 04','customer-harbor-004@customer.example','월간 서비스 점검 및 운영 지원. 체험용 고객 데이터입니다.','Monthly service review and operational support. Fictional demonstration customer.','2026-09-01T09:00:00Z');
INSERT INTO lab.customer_activity VALUES ('customer-harbor-004-1','customer-harbor-004','1','2026-09-01T09:00:00Z','서비스 시작','Service onboarding','고객 포털 이용 절차를 안내했습니다.','Reviewed the customer portal onboarding process.');
INSERT INTO lab.customer_activity VALUES ('customer-harbor-004-2','customer-harbor-004','1','2026-09-02T09:00:00Z','운영 점검','Operations review','월간 운영 현황과 다음 점검 일정을 확인했습니다.','Reviewed monthly operations and the next service review.');
INSERT INTO lab.business_customer VALUES ('customer-harbor-005','1','harbor','푸른 제조 Harbor','Pureun Manufacturing Harbor','제조','Manufacturing','서울','Seoul','CONFIDENTIAL','Demo Contact 05','customer-harbor-005@customer.example','월간 서비스 점검 및 운영 지원. 체험용 고객 데이터입니다.','Monthly service review and operational support. Fictional demonstration customer.','2026-09-01T09:00:00Z');
INSERT INTO lab.customer_activity VALUES ('customer-harbor-005-1','customer-harbor-005','1','2026-09-01T09:00:00Z','서비스 시작','Service onboarding','고객 포털 이용 절차를 안내했습니다.','Reviewed the customer portal onboarding process.');
INSERT INTO lab.customer_activity VALUES ('customer-harbor-005-2','customer-harbor-005','1','2026-09-02T09:00:00Z','운영 점검','Operations review','월간 운영 현황과 다음 점검 일정을 확인했습니다.','Reviewed monthly operations and the next service review.');
INSERT INTO lab.business_customer VALUES ('customer-harbor-006','1','harbor','모아 서비스 Harbor','Moa Services Harbor','서비스','Services','부산','Busan','CONFIDENTIAL','Demo Contact 06','customer-harbor-006@customer.example','월간 서비스 점검 및 운영 지원. 체험용 고객 데이터입니다.','Monthly service review and operational support. Fictional demonstration customer.','2026-09-01T09:00:00Z');
INSERT INTO lab.customer_activity VALUES ('customer-harbor-006-1','customer-harbor-006','1','2026-09-01T09:00:00Z','서비스 시작','Service onboarding','고객 포털 이용 절차를 안내했습니다.','Reviewed the customer portal onboarding process.');
INSERT INTO lab.customer_activity VALUES ('customer-harbor-006-2','customer-harbor-006','1','2026-09-02T09:00:00Z','운영 점검','Operations review','월간 운영 현황과 다음 점검 일정을 확인했습니다.','Reviewed monthly operations and the next service review.');
INSERT INTO lab.business_customer VALUES ('customer-summit-001','1','summit','누리 리테일 Summit','Nuri Retail Summit','유통','Retail','서울','Seoul','CONFIDENTIAL','Demo Contact 01','customer-summit-001@customer.example','월간 서비스 점검 및 운영 지원. 체험용 고객 데이터입니다.','Monthly service review and operational support. Fictional demonstration customer.','2026-09-01T09:00:00Z');
INSERT INTO lab.customer_activity VALUES ('customer-summit-001-1','customer-summit-001','1','2026-09-01T09:00:00Z','서비스 시작','Service onboarding','고객 포털 이용 절차를 안내했습니다.','Reviewed the customer portal onboarding process.');
INSERT INTO lab.customer_activity VALUES ('customer-summit-001-2','customer-summit-001','1','2026-09-02T09:00:00Z','운영 점검','Operations review','월간 운영 현황과 다음 점검 일정을 확인했습니다.','Reviewed monthly operations and the next service review.');
INSERT INTO lab.business_customer VALUES ('customer-summit-002','1','summit','온길 물류 Summit','Ongil Logistics Summit','물류','Logistics','부산','Busan','CONFIDENTIAL','Demo Contact 02','customer-summit-002@customer.example','월간 서비스 점검 및 운영 지원. 체험용 고객 데이터입니다.','Monthly service review and operational support. Fictional demonstration customer.','2026-09-01T09:00:00Z');
INSERT INTO lab.customer_activity VALUES ('customer-summit-002-1','customer-summit-002','1','2026-09-01T09:00:00Z','서비스 시작','Service onboarding','고객 포털 이용 절차를 안내했습니다.','Reviewed the customer portal onboarding process.');
INSERT INTO lab.customer_activity VALUES ('customer-summit-002-2','customer-summit-002','1','2026-09-02T09:00:00Z','운영 점검','Operations review','월간 운영 현황과 다음 점검 일정을 확인했습니다.','Reviewed monthly operations and the next service review.');
INSERT INTO lab.business_customer VALUES ('customer-summit-003','1','summit','다온 스튜디오 Summit','Daon Studio Summit','디자인','Design','서울','Seoul','CONFIDENTIAL','Demo Contact 03','customer-summit-003@customer.example','월간 서비스 점검 및 운영 지원. 체험용 고객 데이터입니다.','Monthly service review and operational support. Fictional demonstration customer.','2026-09-01T09:00:00Z');
INSERT INTO lab.customer_activity VALUES ('customer-summit-003-1','customer-summit-003','1','2026-09-01T09:00:00Z','서비스 시작','Service onboarding','고객 포털 이용 절차를 안내했습니다.','Reviewed the customer portal onboarding process.');
INSERT INTO lab.customer_activity VALUES ('customer-summit-003-2','customer-summit-003','1','2026-09-02T09:00:00Z','운영 점검','Operations review','월간 운영 현황과 다음 점검 일정을 확인했습니다.','Reviewed monthly operations and the next service review.');
INSERT INTO lab.business_customer VALUES ('customer-summit-004','1','summit','마루 교육 Summit','Maru Learning Summit','교육','Education','부산','Busan','CONFIDENTIAL','Demo Contact 04','customer-summit-004@customer.example','월간 서비스 점검 및 운영 지원. 체험용 고객 데이터입니다.','Monthly service review and operational support. Fictional demonstration customer.','2026-09-01T09:00:00Z');
INSERT INTO lab.customer_activity VALUES ('customer-summit-004-1','customer-summit-004','1','2026-09-01T09:00:00Z','서비스 시작','Service onboarding','고객 포털 이용 절차를 안내했습니다.','Reviewed the customer portal onboarding process.');
INSERT INTO lab.customer_activity VALUES ('customer-summit-004-2','customer-summit-004','1','2026-09-02T09:00:00Z','운영 점검','Operations review','월간 운영 현황과 다음 점검 일정을 확인했습니다.','Reviewed monthly operations and the next service review.');
INSERT INTO lab.business_customer VALUES ('customer-summit-005','1','summit','푸른 제조 Summit','Pureun Manufacturing Summit','제조','Manufacturing','서울','Seoul','CONFIDENTIAL','Demo Contact 05','customer-summit-005@customer.example','월간 서비스 점검 및 운영 지원. 체험용 고객 데이터입니다.','Monthly service review and operational support. Fictional demonstration customer.','2026-09-01T09:00:00Z');
INSERT INTO lab.customer_activity VALUES ('customer-summit-005-1','customer-summit-005','1','2026-09-01T09:00:00Z','서비스 시작','Service onboarding','고객 포털 이용 절차를 안내했습니다.','Reviewed the customer portal onboarding process.');
INSERT INTO lab.customer_activity VALUES ('customer-summit-005-2','customer-summit-005','1','2026-09-02T09:00:00Z','운영 점검','Operations review','월간 운영 현황과 다음 점검 일정을 확인했습니다.','Reviewed monthly operations and the next service review.');
INSERT INTO lab.business_customer VALUES ('customer-summit-006','1','summit','모아 서비스 Summit','Moa Services Summit','서비스','Services','부산','Busan','CONFIDENTIAL','Demo Contact 06','customer-summit-006@customer.example','월간 서비스 점검 및 운영 지원. 체험용 고객 데이터입니다.','Monthly service review and operational support. Fictional demonstration customer.','2026-09-01T09:00:00Z');
INSERT INTO lab.customer_activity VALUES ('customer-summit-006-1','customer-summit-006','1','2026-09-01T09:00:00Z','서비스 시작','Service onboarding','고객 포털 이용 절차를 안내했습니다.','Reviewed the customer portal onboarding process.');
INSERT INTO lab.customer_activity VALUES ('customer-summit-006-2','customer-summit-006','1','2026-09-02T09:00:00Z','운영 점검','Operations review','월간 운영 현황과 다음 점검 일정을 확인했습니다.','Reviewed monthly operations and the next service review.');
