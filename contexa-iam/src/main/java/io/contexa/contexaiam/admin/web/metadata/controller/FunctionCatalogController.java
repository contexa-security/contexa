package io.contexa.contexaiam.admin.web.metadata.controller;

import io.contexa.contexaiam.admin.web.metadata.service.FunctionCatalogService;
import io.contexa.contexaiam.domain.dto.FunctionCatalogUpdateDto;
import io.contexa.contexaiam.resource.ResourceEnhancementService;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Controller;

@Slf4j
@Controller
@RequestMapping("/admin/catalog")
public class FunctionCatalogController {

    private final ResourceRegistryService resourceRegistryService;
    private final ResourceEnhancementService resourceEnhancementService;
    private final FunctionCatalogService functionCatalogService;

    public FunctionCatalogController(@Lazy ResourceRegistryService resourceRegistryService,
                                   ResourceEnhancementService resourceEnhancementService,
                                   FunctionCatalogService functionCatalogService) {
        this.resourceRegistryService = resourceRegistryService;
        this.resourceEnhancementService = resourceEnhancementService;
        this.functionCatalogService = functionCatalogService;
    }

    @GetMapping("/unconfirmed")
    public String unconfirmedListPage(Model model) {
        model.addAttribute("unconfirmedFunctions", functionCatalogService.findUnconfirmedFunctions());
        model.addAttribute("functionGroups", functionCatalogService.getAllFunctionGroups());
        return "admin/catalog-unconfirmed";
    }

    @PostMapping("/{catalogId}/confirm")
    public String confirmFunction(@PathVariable Long catalogId, @RequestParam Long groupId, RedirectAttributes ra) {
        functionCatalogService.confirmFunction(catalogId, groupId);
        ra.addFlashAttribute("message", "기능이 성공적으로 확인 및 등록되었습니다.");
        return "redirect:/admin/catalog/unconfirmed";
    }

    @GetMapping
    public String catalogListPage(Model model) {
        model.addAttribute("catalogData", functionCatalogService.getGroupedCatalogs());
        model.addAttribute("functionGroups", functionCatalogService.getAllFunctionGroups());
        
        if (model.containsAttribute("message")) {
            model.addAttribute("message", model.asMap().get("message"));
        }
        if (model.containsAttribute("errorMessage")) {
            model.addAttribute("errorMessage", model.asMap().get("errorMessage"));
        }
        return "admin/permissions-catalog"; 
    }

    @PostMapping("/{id}/update")
    public String updateCatalogItem(@PathVariable Long id, @ModelAttribute FunctionCatalogUpdateDto dto, RedirectAttributes ra) {
        functionCatalogService.updateCatalog(id, dto);
        ra.addFlashAttribute("message", "기능(ID: " + id + ") 정보가 성공적으로 업데이트되었습니다.");
        return "redirect:/admin/catalog";
    }

    @PostMapping("/refresh")
    public String refreshResources(RedirectAttributes ra) {
        try {
                        
            resourceEnhancementService.refreshResources();
            
            ra.addFlashAttribute("message", "시스템의 모든 기능을 성공적으로 다시 스캔했습니다.");
                        
        } catch (Exception e) {
            log.error("리소스 새로고침 실패", e);
            ra.addFlashAttribute("errorMessage", "리소스 새로고침 중 오류가 발생했습니다: " + e.getMessage());
        }
        
        return "redirect:/admin/catalog";
    }

    @PostMapping("/batch-status")
    @ResponseBody
    public ResponseEntity<?> batchUpdateStatus(@RequestBody Map<String, Object> payload) {
        List<Integer> idsAsInteger = (List<Integer>) payload.get("ids");
        List<Long> ids = idsAsInteger.stream().map(Integer::longValue).toList();
        String status = (String) payload.get("status");
        functionCatalogService.batchUpdateStatus(ids, status);
        return ResponseEntity.ok(Map.of("message", "선택된 기능들의 상태가 성공적으로 변경되었습니다."));
    }
}
