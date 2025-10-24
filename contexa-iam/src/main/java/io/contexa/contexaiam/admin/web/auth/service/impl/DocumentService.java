package io.contexa.contexaiam.admin.web.auth.service.impl;

import io.contexa.contexaiam.domain.entity.Document;
import io.contexa.contexaiam.repository.DocumentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class DocumentService {

    private final DocumentRepository documentRepository;

    /**
     * 특정 문서의 소유자가 현재 사용자인지 확인합니다.
     * CustomPermissionEvaluator에서 호출됩니다.
     * @param documentId 확인할 문서의 ID
     * @param username 현재 인증된 사용자명
     * @return 현재 사용자가 문서의 소유자이면 true, 아니면 false
     */
    public boolean isUserOwnerOfDocument(Serializable documentId, String username) {
        if (documentId == null || username == null) {
            log.warn("Ownership check: documentId or username is null. Denying access.");
            return false;
        }
        try {
            Long id = (Long) documentId; // Serializable을 Long으로 안전하게 캐스팅
            Optional<Document> documentOpt = documentRepository.findById(id);

            if (documentOpt.isPresent()) {
                Document document = documentOpt.get();
                // 문서 엔티티의 ownerUsername 필드와 현재 사용자명을 비교
                if (document.getOwnerUsername() != null && document.getOwnerUsername().equals(username)) {
                    log.debug("User '{}' is owner of document ID {}. Access granted by ownership check.", username, documentId);
                    return true;
                } else {
                    log.debug("User '{}' is NOT owner of document ID {}. Document owner: '{}'. Access denied by ownership check.", username, documentId, document.getOwnerUsername());
                    return false;
                }
            } else {
                log.warn("Document with ID {} not found for ownership check. Denying access.", documentId);
                return false; // 문서가 DB에 없으면 접근 거부
            }
        } catch (ClassCastException e) {
            log.error("Document ID for ownership check is not of expected type Long: {}", documentId, e);
            return false;
        } catch (Exception e) {
            log.error("Error during document ownership check for ID {}: {}", documentId, e.getMessage(), e);
            return false;
        }
    }

    /**
     * 새로운 문서를 생성합니다.
     * @param document 생성할 Document 엔티티
     * @return 생성된 Document 엔티티
     */
    @Transactional
    public Document createDocument(Document document) {
        log.info("Creating new document with title: '{}' by owner: '{}'", document.getTitle(), document.getOwnerUsername());
        document.setCreatedAt(LocalDateTime.now()); // 생성 시간 자동 설정
        return documentRepository.save(document);
    }

    /**
     * ID로 문서를 조회합니다.
     * @param id 조회할 문서 ID
     * @return 해당 Document 엔티티 (Optional)
     */
    public Optional<Document> getDocumentById(Long id) {
        log.debug("Fetching document with ID: {}", id);
        return documentRepository.findById(id);
    }

    /**
     * 모든 문서를 조회합니다.
     * @return 모든 Document 엔티티 리스트
     */
    public List<Document> getAllDocuments() {
        return documentRepository.findAll();
    }

    /**
     * 문서 내용을 업데이트합니다.
     * @param id 업데이트할 문서 ID
     * @param newContent 새로운 내용
     * @return 업데이트된 Document 엔티티 (Optional)
     */
    @Transactional
    public Optional<Document> updateDocumentContent(Long id, String newContent) {
        return documentRepository.findById(id).map(document -> {
            document.setContent(newContent);
            document.setUpdatedAt(LocalDateTime.now()); // 업데이트 시간 설정
            log.info("Document ID {} content updated.", id);
            return documentRepository.save(document);
        });
    }

    /**
     * ID로 문서를 삭제합니다.
     * @param id 삭제할 문서 ID
     */
    @Transactional
    public void deleteDocument(Long id) {
        log.info("Deleting document with ID: {}", id);
        documentRepository.deleteById(id);
    }
}