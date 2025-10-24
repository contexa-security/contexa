-- 벡터 차원 1536 → 1024로 변경
-- text-embedding-3-small이 실제로는 1024차원을 반환하는 경우

-- 1. 기존 테이블 백업 (선택사항)
-- CREATE TABLE iam_vectors_backup AS SELECT * FROM iam_vectors;

-- 2. 기존 벡터 데이터 삭제 (차원 불일치로 인한 오류 방지)
TRUNCATE TABLE vector_store;

-- 3. 벡터 차원 변경을 위한 컬럼 재생성
ALTER TABLE vector_store DROP COLUMN IF EXISTS embedding;
ALTER TABLE vector_store ADD COLUMN embedding vector(1024);

-- 4. 인덱스 재생성 (성능 최적화)
DROP INDEX IF EXISTS iam_vectors_embedding_idx;
CREATE INDEX iam_vectors_embedding_idx ON vector_store
USING hnsw (embedding vector_cosine_ops);

-- 확인 쿼리
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'iam_vectors' AND column_name = 'embedding';
