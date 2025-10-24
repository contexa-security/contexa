package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.impl.DocumentService;
import io.contexa.contexaiam.domain.entity.Document;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Slf4j
@Controller
@RequestMapping("/admin/docs") // 그룹 관리를 위한 공통 경로 설정
@RequiredArgsConstructor
public class DocumentController {

    private final DocumentService documentService;

    @PostMapping
    public String createDocument(Document document) {
        documentService.createDocument(document);
        return "admin/document";
    }

    @GetMapping("/{id}")
    public String createDocument(@PathVariable Long id) {
        documentService.getDocumentById(id);
        return "admin/document";
    }
}
