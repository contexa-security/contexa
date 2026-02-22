/**
 * SOAR Session State Manager
 * 
 * Reactive state management with observer pattern
 * Handles session persistence, recovery, and synchronization
 */
class SessionStateManager {
    constructor() {
        this.state = this.createInitialState();
        this.observers = new Map();
        this.stateHistory = [];
        this.maxHistorySize = 50;
        this.syncInterval = null;
        this.localStorageKey = 'soar-session-state';
        
        // Create reactive proxy
        this.reactiveState = this.createReactiveProxy(this.state);
        
        // Initialize from localStorage if available
        this.loadPersistedState();
        
        // Start periodic sync
        this.startPeriodicSync();
    }

    /**
     * Create initial state structure
     */
    createInitialState() {
        return {
            // Session information
            session: {
                id: null,
                conversationId: null,
                status: 'IDLE', // IDLE, INITIALIZING, ACTIVE, COMPLETED, FAILED
                startTime: null,
                endTime: null,
                duration: 0
            },
            
            // Pipeline state
            pipeline: {
                currentStage: null,
                completedStages: [],
                progress: 0,
                stages: {
                    PREPROCESSING: { status: 'pending', progress: 0, startTime: null, endTime: null },
                    CONTEXT_RETRIEVAL: { status: 'pending', progress: 0, startTime: null, endTime: null },
                    PROMPT_GENERATION: { status: 'pending', progress: 0, startTime: null, endTime: null },
                    LLM_EXECUTION: { status: 'pending', progress: 0, startTime: null, endTime: null },
                    RESPONSE_PARSING: { status: 'pending', progress: 0, startTime: null, endTime: null },
                    POSTPROCESSING: { status: 'pending', progress: 0, startTime: null, endTime: null }
                }
            },
            
            // Tool execution state
            tools: {
                executed: [],
                pending: [],
                approved: [],
                rejected: [],
                currentTool: null
            },
            
            // Approval state
            approvals: {
                pending: [],
                history: [],
                autoApprove: false,
                defaultReason: ''
            },
            
            // MCP server status
            mcpServers: {
                context7: false,
                sequential: false,
                magic: false,
                playwright: false,
                lastCheck: null
            },
            
            // Performance metrics
            metrics: {
                totalDuration: 0,
                stageTimings: {},
                toolExecutionTime: 0,
                approvalWaitTime: 0,
                networkLatency: []
            },
            
            // Error state
            errors: {
                count: 0,
                lastError: null,
                history: []
            },
            
            // UI state
            ui: {
                modalVisible: false,
                pipelineVisible: true,
                toolLogVisible: true,
                monitoringVisible: false,
                selectedTab: 'pipeline'
            }
        };
    }

    /**
     * Create reactive proxy for state
     */
    createReactiveProxy(target, path = []) {
        const self = this;
        
        return new Proxy(target, {
            get(obj, prop) {
                const value = obj[prop];
                const currentPath = [...path, prop];
                
                if (value !== null && typeof value === 'object' && !(value instanceof Date)) {
                    return self.createReactiveProxy(value, currentPath);
                }
                
                return value;
            },
            
            set(obj, prop, value) {
                const oldValue = obj[prop];
                const currentPath = [...path, prop];
                
                // Only update if value actually changed
                if (oldValue !== value) {
                    obj[prop] = value;
                    
                    // Notify observers
                    self.notifyObservers(currentPath, value, oldValue);
                    
                    // Add to history
                    self.addToHistory({
                        path: currentPath,
                        oldValue,
                        newValue: value,
                        timestamp: Date.now()
                    });
                    
                    // Persist to localStorage
                    self.persistState();
                }
                
                return true;
            }
        });
    }

    /**
     * Subscribe to state changes
     */
    subscribe(path, callback) {
        const pathKey = Array.isArray(path) ? path.join('.') : path;
        
        if (!this.observers.has(pathKey)) {
            this.observers.set(pathKey, []);
        }
        
        this.observers.get(pathKey).push(callback);
        
        // Return unsubscribe function
        return () => {
            const callbacks = this.observers.get(pathKey);
            if (callbacks) {
                const index = callbacks.indexOf(callback);
                if (index > -1) {
                    callbacks.splice(index, 1);
                }
            }
        };
    }

    /**
     * Notify observers of state changes
     */
    notifyObservers(path, newValue, oldValue) {
        const pathKey = path.join('.');
        
        // Notify exact path observers
        if (this.observers.has(pathKey)) {
            this.observers.get(pathKey).forEach(callback => {
                try {
                    callback(newValue, oldValue, path);
                } catch (error) {
                    console.error('Error in state observer:', error);
                }
            });
        }
        
        // Notify parent path observers (for nested changes)
        for (let i = path.length - 1; i > 0; i--) {
            const parentPath = path.slice(0, i).join('.');
            if (this.observers.has(parentPath)) {
                const parentValue = this.getValueAtPath(path.slice(0, i));
                this.observers.get(parentPath).forEach(callback => {
                    try {
                        callback(parentValue, null, path.slice(0, i));
                    } catch (error) {
                        console.error('Error in parent observer:', error);
                    }
                });
            }
        }
        
        // Notify wildcard observers
        if (this.observers.has('*')) {
            this.observers.get('*').forEach(callback => {
                try {
                    callback(this.reactiveState, null, path);
                } catch (error) {
                    console.error('Error in wildcard observer:', error);
                }
            });
        }
    }

    /**
     * Get value at path
     */
    getValueAtPath(path) {
        return path.reduce((obj, key) => obj ? obj[key] : undefined, this.reactiveState);
    }

    /**
     * Set value at path
     */
    setValueAtPath(path, value) {
        const pathArray = Array.isArray(path) ? path : path.split('.');
        const lastKey = pathArray.pop();
        const target = pathArray.reduce((obj, key) => {
            if (!obj[key]) obj[key] = {};
            return obj[key];
        }, this.reactiveState);
        
        target[lastKey] = value;
    }

    /**
     * Add to state history
     */
    addToHistory(change) {
        this.stateHistory.push(change);
        
        // Limit history size
        if (this.stateHistory.length > this.maxHistorySize) {
            this.stateHistory.shift();
        }
    }

    /**
     * Persist state to localStorage
     */
    persistState() {
        try {
            const stateToSave = {
                state: this.state,
                timestamp: Date.now()
            };
            localStorage.setItem(this.localStorageKey, JSON.stringify(stateToSave));
        } catch (error) {
            console.error('Failed to persist state:', error);
        }
    }

    /**
     * Load persisted state from localStorage
     */
    loadPersistedState() {
        try {
            const saved = localStorage.getItem(this.localStorageKey);
            if (saved) {
                const { state, timestamp } = JSON.parse(saved);
                
                // Only load if less than 1 hour old
                if (Date.now() - timestamp < 3600000) {
                    // Merge with initial state to ensure all properties exist
                    this.state = this.mergeStates(this.createInitialState(), state);
                    this.reactiveState = this.createReactiveProxy(this.state);
                    console.log('Loaded persisted state from localStorage');
                }
            }
        } catch (error) {
            console.error('Failed to load persisted state:', error);
        }
    }

    /**
     * Merge two state objects
     */
    mergeStates(target, source) {
        const result = { ...target };
        
        for (const key in source) {
            if (source.hasOwnProperty(key)) {
                if (source[key] !== null && typeof source[key] === 'object' && !(source[key] instanceof Date)) {
                    result[key] = this.mergeStates(target[key] || {}, source[key]);
                } else {
                    result[key] = source[key];
                }
            }
        }
        
        return result;
    }

    /**
     * Start periodic synchronization with server
     */
    startPeriodicSync(interval = 5000) {
        this.stopPeriodicSync();
        
        this.syncInterval = setInterval(() => {
            if (this.reactiveState.session.id && this.reactiveState.session.status === 'ACTIVE') {
                this.syncWithServer();
            }
        }, interval);
    }

    /**
     * Stop periodic synchronization
     */
    stopPeriodicSync() {
        if (this.syncInterval) {
            clearInterval(this.syncInterval);
            this.syncInterval = null;
        }
    }

    /**
     * Synchronize with server
     */
    async syncWithServer() {
        if (!this.reactiveState.session.id) return;
        
        try {
            const response = await fetch(`/api/soar/simulation/session/${this.reactiveState.session.id}`);
            if (response.ok) {
                const serverState = await response.json();
                this.mergeServerState(serverState);
            }
        } catch (error) {
            console.error('Failed to sync with server:', error);
        }
    }

    /**
     * Merge server state with local state
     */
    mergeServerState(serverState) {
        // Update session status
        if (serverState.status) {
            this.reactiveState.session.status = serverState.status;
        }
        
        // Update pipeline progress
        if (serverState.currentStage) {
            this.reactiveState.pipeline.currentStage = serverState.currentStage;
        }
        
        if (serverState.progress !== undefined) {
            this.reactiveState.pipeline.progress = serverState.progress;
        }
        
        // Update executed tools
        if (serverState.executedTools) {
            this.reactiveState.tools.executed = serverState.executedTools;
        }
        
        // Update pending approvals
        if (serverState.pendingApprovals) {
            this.reactiveState.approvals.pending = serverState.pendingApprovals;
        }
        
        // Update MCP status
        if (serverState.mcpServersStatus) {
            this.reactiveState.mcpServers = {
                ...serverState.mcpServersStatus,
                lastCheck: Date.now()
            };
        }
    }

    /**
     * Reset state
     */
    reset() {
        this.state = this.createInitialState();
        this.reactiveState = this.createReactiveProxy(this.state);
        this.stateHistory = [];
        this.persistState();
        this.notifyObservers(['*'], this.reactiveState, null);
    }

    /**
     * Get current state (read-only)
     */
    getState() {
        return JSON.parse(JSON.stringify(this.state));
    }

    /**
     * Get state history
     */
    getHistory() {
        return [...this.stateHistory];
    }

    /**
     * Batch update multiple state properties
     */
    batchUpdate(updates) {
        Object.entries(updates).forEach(([path, value]) => {
            this.setValueAtPath(path, value);
        });
    }

    /**
     * Start new session
     */
    startSession(sessionId, conversationId) {
        this.batchUpdate({
            'session.id': sessionId,
            'session.conversationId': conversationId,
            'session.status': 'INITIALIZING',
            'session.startTime': Date.now(),
            'session.endTime': null,
            'pipeline.progress': 0,
            'tools.executed': [],
            'errors.count': 0
        });
    }

    /**
     * End session
     */
    endSession(status = 'COMPLETED') {
        const endTime = Date.now();
        const duration = this.reactiveState.session.startTime ? 
            endTime - this.reactiveState.session.startTime : 0;
        
        this.batchUpdate({
            'session.status': status,
            'session.endTime': endTime,
            'session.duration': duration,
            'metrics.totalDuration': duration
        });
    }

    /**
     * Update pipeline stage
     */
    updatePipelineStage(stageName, progress, status = 'active') {
        const stageKey = `pipeline.stages.${stageName}`;
        
        if (!this.reactiveState.pipeline.stages[stageName].startTime && status === 'active') {
            this.setValueAtPath(`${stageKey}.startTime`, Date.now());
        }
        
        this.setValueAtPath(`${stageKey}.status`, status);
        this.setValueAtPath(`${stageKey}.progress`, progress);
        
        if (status === 'completed') {
            this.setValueAtPath(`${stageKey}.endTime`, Date.now());
            
            // Add to completed stages
            const completed = [...this.reactiveState.pipeline.completedStages];
            if (!completed.includes(stageName)) {
                completed.push(stageName);
                this.reactiveState.pipeline.completedStages = completed;
            }
        }
        
        // Update overall progress
        const stages = Object.values(this.reactiveState.pipeline.stages);
        const totalProgress = stages.reduce((sum, stage) => sum + stage.progress, 0);
        this.reactiveState.pipeline.progress = Math.round(totalProgress / stages.length);
    }

    /**
     * Add error
     */
    addError(error) {
        const errorEntry = {
            message: error.message || String(error),
            timestamp: Date.now(),
            stack: error.stack
        };
        
        this.reactiveState.errors.lastError = errorEntry;
        this.reactiveState.errors.history = [...this.reactiveState.errors.history, errorEntry];
        this.reactiveState.errors.count = this.reactiveState.errors.count + 1;
        
        // Limit error history
        if (this.reactiveState.errors.history.length > 10) {
            this.reactiveState.errors.history.shift();
        }
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SessionStateManager;
}

// Make available globally for browser environment
if (typeof window !== 'undefined') {
    window.SessionStateManager = SessionStateManager;
}