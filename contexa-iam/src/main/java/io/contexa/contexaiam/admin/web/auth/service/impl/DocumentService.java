package io.contexa.contexaiam.admin.web.auth.service.impl;

import io.contexa.contexaiam.domain.entity.Document;
import io.contexa.contexaiam.repository.DocumentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
@Slf4j
public class DocumentService {

    private final DocumentRepository documentRepository;

    public boolean isUserOwnerOfDocument(Serializable documentId, String username) {
        if (documentId == null || username == null) {
            log.warn("Ownership check: documentId or username is null. Denying access.");
            return false;
        }
        try {
            Long id = (Long) documentId; 
            Optional<Document> documentOpt = documentRepository.findById(id);

            if (documentOpt.isPresent()) {
                Document document = documentOpt.get();
                
                if (document.getOwnerUsername() != null && document.getOwnerUsername().equals(username)) {
                                        return true;
                } else {
                                        return false;
                }
            } else {
                log.warn("Document with ID {} not found for ownership check. Denying access.", documentId);
                return false; 
            }
        } catch (ClassCastException e) {
            log.error("Document ID for ownership check is not of expected type Long: {}", documentId, e);
            return false;
        } catch (Exception e) {
            log.error("Error during document ownership check for ID {}: {}", documentId, e.getMessage(), e);
            return false;
        }
    }

    @Transactional
    public Document createDocument(Document document) {
                document.setCreatedAt(LocalDateTime.now()); 
        return documentRepository.save(document);
    }

    public Optional<Document> getDocumentById(Long id) {
                return documentRepository.findById(id);
    }

    public List<Document> getAllDocuments() {
        return documentRepository.findAll();
    }

    @Transactional
    public Optional<Document> updateDocumentContent(Long id, String newContent) {
        return documentRepository.findById(id).map(document -> {
            document.setContent(newContent);
            document.setUpdatedAt(LocalDateTime.now()); 
                        return documentRepository.save(document);
        });
    }

    @Transactional
    public void deleteDocument(Long id) {
                documentRepository.deleteById(id);
    }
}