/**
 * SOAR System Debug Helper
 * 
 * Quick debugging script to check system status
 */

(function() {
    'use strict';
    
    console.log('=== SOAR System Debug Check ===');
    
    // Check 1: Enhanced components loaded
    console.log('1. Enhanced Components:');
    const components = [
        'EnhancedWebSocketClient',
        'SoarApprovalModal',
        'SessionStateManager',
        'SoarErrorHandler',
        'SoarPipelineVisualization',
        'SoarMonitoringDashboard'
    ];
    
    components.forEach(comp => {
        const exists = typeof window[comp] !== 'undefined';
        console.log(`   ${exists ? '✅' : '❌'} ${comp}`);
    });
    
    // Check 2: Main SOAR instance
    console.log('\n2. SOAR Enhanced Instance:');
    if (window.soarEnhanced) {
        console.log('   soarEnhanced exists');
        
        // Check WebSocket
        const ws = window.soarEnhanced.websocket;
        if (ws) {
            console.log('   WebSocket client exists');
            console.log(`   📡 Connection state: ${ws.getConnectionState()}`);
            console.log(`   📡 Is connected: ${ws.isConnected()}`);
            
            // Try to connect if not connected
            if (!ws.isConnected()) {
                console.log('   Attempting to connect WebSocket...');
                ws.connect().then(() => {
                    console.log('   WebSocket connected successfully!');
                }).catch(err => {
                    console.error('   WebSocket connection failed:', err);
                });
            }
        } else {
            console.log('   WebSocket client not found');
        }
        
        // Check state manager
        const state = window.soarEnhanced.stateManager;
        if (state) {
            console.log('   State Manager exists');
            console.log('   📊 Current state:', state.getState());
        } else {
            console.log('   State Manager not found');
        }
        
    } else {
        console.log('   soarEnhanced NOT found');
        console.log('   ℹ️ Attempting manual initialization...');
        
        // Try manual initialization
        if (typeof SoarEnhancedSystem !== 'undefined') {
            window.soarEnhanced = new SoarEnhancedSystem();
            window.soarEnhanced.initialize().then(() => {
                console.log('   Manual initialization successful!');
            }).catch(err => {
                console.error('   Manual initialization failed:', err);
            });
        } else {
            console.error('   SoarEnhancedSystem class not found');
        }
    }
    
    // Check 3: DOM Elements
    console.log('\n3. DOM Elements:');
    const elements = [
        'analyzeSoarBtn',
        'sessionStatus',
        'wsStatus',
        'currentSessionId',
        'websocketMessages',
        'enhancedControlPanel'
    ];
    
    elements.forEach(id => {
        const el = document.getElementById(id);
        console.log(`   ${el ? '✅' : '❌'} #${id}`);
    });
    
    // Check 4: Test WebSocket message
    console.log('\n4. Testing WebSocket:');
    if (window.soarEnhanced?.websocket?.isConnected()) {
        console.log('   📤 Sending test message...');
        window.soarEnhanced.websocket.send('/app/test', { 
            message: 'Debug test', 
            timestamp: new Date().toISOString() 
        });
    } else {
        console.log('   Cannot send test - WebSocket not connected');
    }
    
    // Check 5: Server endpoints
    console.log('\n5. Testing Server Endpoints:');
    
    // Test MCP status endpoint
    fetch('/api/soar/simulation/mcp-status')
        .then(res => {
            console.log(`   ${res.ok ? '✅' : '❌'} MCP Status endpoint: ${res.status}`);
            return res.json();
        })
        .then(data => {
            console.log('   📊 MCP Status:', data);
        })
        .catch(err => {
            console.error('   MCP Status endpoint error:', err);
        });
    
    console.log('\n=== Debug Check Complete ===');
    console.log('💡 Tip: Run window.soarDebug.testSimulation() to test simulation');
    
    // Export debug functions
    window.soarDebug = {
        testSimulation: function() {
            console.log('🚀 Starting test simulation...');
            
            const testData = {
                incidentId: `TEST-${Date.now()}`,
                threatType: 'Debug Test',
                description: 'This is a debug test simulation',
                affectedAssets: ['test-asset-1'],
                detectedSource: 'Debug Console',
                severity: 'LOW',
                organizationId: 'test_org',
                userQuery: 'Debug test query',
                metadata: {
                    source: 'Debug Helper'
                }
            };
            
            fetch('/api/soar/simulation/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(testData)
            })
            .then(res => {
                console.log(`Response status: ${res.status}`);
                if (!res.ok) {
                    return res.text().then(text => {
                        throw new Error(`Server error: ${text}`);
                    });
                }
                return res.json();
            })
            .then(data => {
                console.log('Simulation started:', data);
            })
            .catch(err => {
                console.error('Simulation failed:', err);
            });
        },
        
        checkAll: function() {
            location.reload();
        },
        
        status: function() {
            if (window.soarEnhanced) {
                return window.soarEnhanced.getSystemStatus();
            }
            return 'System not initialized';
        }
    };
    
})();