/**
 * SOAR System Initialization
 * 
 * 중앙 매니저를 통해 SOAR 시스템을 초기화합니다.
 * 모든 컴포넌트는 SoarManager를 통해 관리됩니다.
 */

(function() {
    'use strict';
    
    // Configuration flag - set to true to use enhanced version
    const USE_ENHANCED_VERSION = true;
    
    // Initialize SOAR system through central manager
    window.addEventListener('DOMContentLoaded', async function() {
        // SoarManager가 로드될 때까지 대기
        let retries = 0;
        const maxRetries = 10;
        
        while (!window.soarManager && retries < maxRetries) {
            console.log(`⏳ SoarManager 로드 대기 중... (${retries + 1}/${maxRetries})`);
            await new Promise(resolve => setTimeout(resolve, 100));
            retries++;
        }
        
        if (!window.soarManager) {
            console.error('SoarManager를 찾을 수 없습니다');
            return;
        }
        
        // SoarManager 설정
        window.soarManager.config.enableEnhanced = USE_ENHANCED_VERSION;
        
        // 중앙 매니저를 통한 초기화
        try {
            await window.soarManager.initialize();
            
            // 버전별 UI 인디케이터 추가
            const statusEl = document.createElement('div');
            statusEl.className = 'soar-version-indicator';
            
            if (USE_ENHANCED_VERSION) {
                statusEl.innerHTML = `
                    <div style="position: fixed; top: 10px; right: 10px; 
                                background: linear-gradient(135deg, #22c55e, #16a34a); 
                                color: white; padding: 0.5rem 1rem; 
                                border-radius: 0.75rem; font-size: 0.75rem; 
                                font-weight: 600; z-index: 10000;
                                box-shadow: 0 4px 12px rgba(34, 197, 94, 0.3);">
                        <i class="fas fa-rocket"></i> Enhanced SOAR v2.0 (Managed)
                    </div>
                `;
            } else {
                statusEl.innerHTML = `
                    <div style="position: fixed; top: 10px; right: 10px; 
                                background: #6b7280; color: white; 
                                padding: 0.5rem 1rem; border-radius: 0.75rem; 
                                font-size: 0.75rem; font-weight: 600; z-index: 10000;">
                        <i class="fas fa-box"></i> Legacy SOAR v1.0 (Managed)
                    </div>
                `;
            }
            
            document.body.appendChild(statusEl);
            console.log('SOAR 시스템이 중앙 매니저를 통해 초기화되었습니다');
            
        } catch (error) {
            console.error('SOAR 시스템 초기화 실패:', error);
        }
    });
    
    // Expose configuration for runtime changes
    window.soarConfig = {
        useEnhanced: USE_ENHANCED_VERSION,
        
        // Method to switch versions (requires page reload)
        switchVersion: function(useEnhanced) {
            this.useEnhanced = useEnhanced;
            localStorage.setItem('soar-use-enhanced', useEnhanced);
            location.reload();
        },
        
        // Check current version through manager
        getCurrentVersion: function() {
            if (window.soarManager) {
                return window.soarManager.config.enableEnhanced ? 'enhanced' : 'legacy';
            }
            return 'unknown';
        },
        
        // Get system status through manager
        getSystemStatus: function() {
            if (window.soarManager) {
                return window.soarManager.getStatus();
            }
            return { version: 'unknown', status: 'manager not initialized' };
        }
    };
    
    // Check localStorage for version preference
    const savedPreference = localStorage.getItem('soar-use-enhanced');
    if (savedPreference !== null) {
        window.soarConfig.useEnhanced = savedPreference === 'true';
    }
    
    console.log(`SOAR System Configuration: ${window.soarConfig.useEnhanced ? 'Enhanced' : 'Legacy'} Mode`);
})();