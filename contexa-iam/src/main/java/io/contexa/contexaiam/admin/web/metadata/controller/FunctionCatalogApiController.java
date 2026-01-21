package io.contexa.contexaiam.admin.web.metadata.controller;

import io.contexa.contexaiam.admin.web.metadata.service.FunctionCatalogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@Slf4j
@RequestMapping("/api/admin/catalog") 
@RequiredArgsConstructor
public class FunctionCatalogApiController {

    private final FunctionCatalogService functionCatalogService;

    @PutMapping("/{catalogId}/status")
    public ResponseEntity<?> updateCatalogStatus(@PathVariable Long catalogId, @RequestBody Map<String, String> payload) {
        try {
            String status = payload.get("status");
            functionCatalogService.updateSingleStatus(catalogId, status);
            return ResponseEntity.ok(Map.of("message", "상태가 성공적으로 변경되었습니다."));
        } catch (Exception e) {
            log.error("개별 상태 업데이트 처리 중 오류 발생. ID: {}", catalogId, e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/batch-status")
    public ResponseEntity<?> batchUpdateStatus(@RequestBody Map<String, Object> payload) {
        try {
            List<Integer> idsAsInteger = (List<Integer>) payload.get("ids");
            List<Long> ids = idsAsInteger.stream().map(Integer::longValue).toList();
            String status = (String) payload.get("status");
            functionCatalogService.batchUpdateStatus(ids, status);
            return ResponseEntity.ok(Map.of("message", "선택된 기능들의 상태가 성공적으로 변경되었습니다."));
        } catch (Exception e) {
            log.error("일괄 상태 업데이트 처리 중 오류 발생", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/confirm-batch")
    public ResponseEntity<?> confirmBatch(@RequestBody List<Map<String, Long>> payload) {
        try {
            functionCatalogService.confirmBatch(payload);
            return ResponseEntity.ok(Map.of("message", "선택된 기능들이 성공적으로 등록되었습니다."));
        } catch (Exception e) {
            log.error("미확인 기능 일괄 등록 중 오류 발생", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}
