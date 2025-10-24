package io.contexa.contexacore.std.rag.service;

import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Spring AI 벡터 저장소 표준 작업 인터페이스
 * 
 * 모든 Lab에서 사용하는 벡터 저장소 작업을 표준화합니다.
 * Spring AI VectorStore API를 완벽하게 준수하며, 
 * 메타데이터 강화, 청킹, 배치 처리 등을 포함합니다.
 * 
 * @since 1.0.0
 */
public interface VectorOperations {
    
    /**
     * 단일 문서를 벡터 저장소에 저장
     * 
     * @param document 저장할 문서
     * @throws VectorStoreException 저장 실패 시
     */
    void storeDocument(Document document);
    
    /**
     * 여러 문서를 배치로 벡터 저장소에 저장
     * 
     * @param documents 저장할 문서 목록
     * @throws VectorStoreException 저장 실패 시
     */
    void storeDocuments(List<Document> documents);
    
    /**
     * 비동기로 단일 문서 저장
     * 
     * @param document 저장할 문서
     * @return 비동기 작업 결과
     */
    CompletableFuture<Void> storeDocumentAsync(Document document);
    
    /**
     * 비동기로 여러 문서 배치 저장
     * 
     * @param documents 저장할 문서 목록
     * @return 비동기 작업 결과
     */
    CompletableFuture<Void> storeDocumentsAsync(List<Document> documents);
    
    /**
     * 유사도 기반 문서 검색
     * 
     * @param query 검색 쿼리
     * @return 유사한 문서 목록
     */
    List<Document> searchSimilar(String query);
    
    /**
     * 필터 조건을 포함한 문서 검색
     * 
     * @param query 검색 쿼리
     * @param filters 메타데이터 필터 조건
     * @return 필터링된 문서 목록
     */
    List<Document> searchSimilar(String query, Map<String, Object> filters);
    
    /**
     * SearchRequest를 사용한 고급 검색
     * 
     * @param searchRequest 검색 요청 객체
     * @return 검색 결과 문서 목록
     */
    List<Document> searchSimilar(SearchRequest searchRequest);
    
    /**
     * 시간 범위 기반 문서 검색
     * 
     * @param query 검색 쿼리
     * @param startTime 시작 시간
     * @param endTime 종료 시간
     * @param documentType 문서 타입 (선택적)
     * @return 시간 범위에 해당하는 문서 목록
     */
    List<Document> searchByTimeRange(String query, LocalDateTime startTime, 
                                    LocalDateTime endTime, String documentType);
    
    /**
     * 문서 삭제
     * 
     * @param documentIds 삭제할 문서 ID 목록
     */
    void deleteDocuments(List<String> documentIds);
    
    /**
     * 문서 업데이트 (삭제 후 재저장)
     * 
     * @param documents 업데이트할 문서 목록
     */
    void updateDocuments(List<Document> documents);
    
    /**
     * 벡터 저장소 통계 조회
     * 
     * @return 저장소 통계 정보
     */
    Map<String, Object> getStatistics();
    
    /**
     * 커스텀 벡터 저장소 예외
     */
    class VectorStoreException extends RuntimeException {
        public VectorStoreException(String message) {
            super(message);
        }
        
        public VectorStoreException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}