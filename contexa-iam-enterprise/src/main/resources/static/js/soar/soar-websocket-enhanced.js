/**
 * Enhanced WebSocket Client for SOAR Simulation
 * 
 * Features:
 * - Automatic reconnection with exponential backoff
 * - Message queuing during disconnections
 * - Heartbeat/keepalive mechanism
 * - All WebSocket topics subscription including missing ones
 * - Connection state management
 */
class EnhancedWebSocketClient {
    constructor(endpoint = '/ws-soar') {
        this.endpoint = endpoint;
        this.stompClient = null;
        this.subscriptions = new Map();
        this.messageQueue = [];
        this.connectionState = 'DISCONNECTED';
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 10;
        this.reconnectDelay = 1000; // Start with 1 second
        this.maxReconnectDelay = 30000; // Max 30 seconds
        this.heartbeatInterval = null;
        this.listeners = new Map();
        this.isIntentionalDisconnect = false;
        this.errorHandler = null; // Error handler integration
        
        // Callback properties for compatibility
        this.onConnect = null;
        this.onDisconnect = null;
    }

    /**
     * Set error handler for integration with SoarErrorHandler
     * @param {SoarErrorHandler} errorHandler - The error handler instance
     */
    setErrorHandler(errorHandler) {
        this.errorHandler = errorHandler;
        console.log('Error handler integrated with WebSocket client');
    }
    
    /**
     * Alias for sendMessage method (for compatibility)
     */
    send(destination, message) {
        return this.sendMessage(destination, message);
    }

    /**
     * Connect to WebSocket with automatic retry
     * @param {Object} options - Connection options (e.g., { timeout: 10000 })
     */
    async connect(options = {}) {
        if (this.connectionState === 'CONNECTED') {
            console.log('WebSocket already connected');
            return Promise.resolve();
        }

        if (this.connectionState === 'CONNECTING') {
            console.log('⏳ WebSocket connection in progress');
            return this.waitForConnection(options.timeout);
        }

        this.connectionState = 'CONNECTING';
        this.isIntentionalDisconnect = false;

        return new Promise((resolve, reject) => {
            try {
                const socket = new SockJS(this.endpoint);
                this.stompClient = Stomp.over(socket);
                
                // Disable debug output in production
                if (!window.DEBUG_MODE) {
                    this.stompClient.debug = null;
                }

                // STOMP 연결 설정 - 서버와 동일한 heartbeat 설정
                this.stompClient.heartbeat.outgoing = 10000; // 10초 (서버와 동일)
                this.stompClient.heartbeat.incoming = 10000; // 10초 (서버와 동일)
                
                this.stompClient.connect({}, 
                    frame => {
                        console.log('WebSocket connected successfully');
                        this.connectionState = 'CONNECTED';
                        this.reconnectAttempts = 0;
                        this.reconnectDelay = 1000;
                        
                        this.subscribeToAllTopics();
                        this.startHeartbeat();
                        this.flushMessageQueue();
                        this.notifyListeners('connected', { frame });
                        
                        // Call onConnect callback if defined
                        if (typeof this.onConnect === 'function') {
                            this.onConnect();
                        }
                        
                        resolve();
                    },
                    error => {
                        console.error('WebSocket connection failed:', error);
                        this.connectionState = 'DISCONNECTED';
                        this.handleConnectionError(error);
                        reject(error);
                    }
                );
            } catch (error) {
                console.error('Failed to create WebSocket connection:', error);
                this.connectionState = 'DISCONNECTED';
                this.handleConnectionError(error);
                reject(error);
            }
        });
    }

    /**
     * Handle connection errors with exponential backoff retry
     */
    handleConnectionError(error) {
        if (this.isIntentionalDisconnect) {
            return;
        }

        // Use error handler if available
        if (this.errorHandler) {
            this.errorHandler.handleError(error, {
                operation: 'WebSocketConnection',
                severity: 'warning'
            });
        }

        this.notifyListeners('error', { error });

        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            const delay = Math.min(
                this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1),
                this.maxReconnectDelay
            );

            console.log(`Reconnection attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts} in ${delay}ms`);
            
            setTimeout(() => {
                this.connect().catch(err => {
                    console.error('Reconnection attempt failed:', err);
                });
            }, delay);
        } else {
            console.error('Max reconnection attempts reached. Please refresh the page.');
            this.notifyListeners('maxReconnectAttemptsReached', {});
            
            // Log critical error through error handler
            if (this.errorHandler) {
                this.errorHandler.handleError(new Error('WebSocket max reconnection attempts reached'), {
                    operation: 'WebSocketReconnection',
                    severity: 'critical'
                });
            }
        }
    }

    /**
     * Subscribe to all SOAR topics including missing ones
     */
    subscribeToAllTopics() {
        console.log('📡 Starting subscription to all SOAR topics...');
        console.log('📡 STOMP client available:', this.stompClient !== null);
        console.log('📡 Connection state:', this.connectionState);
        
        const topics = [
            // Core topics
            { path: '/topic/soar/pipeline', handler: 'pipeline' },
            { path: '/topic/soar/tools', handler: 'tools' },
            { path: '/topic/soar/approvals', handler: 'approvals' },
            { path: '/topic/soar/events', handler: 'events' },
            { path: '/topic/soar/complete', handler: 'complete' },
            { path: '/topic/soar/error', handler: 'error' },
            
            // Session management topics
            { path: '/topic/soar/sessions', handler: 'sessions' },
            
            // Additional monitoring topics
            { path: '/topic/soar/session-status', handler: 'sessionStatus' },
            { path: '/topic/soar/mcp-status', handler: 'mcpStatus' },
            { path: '/topic/soar/performance', handler: 'performance' }
        ];

        topics.forEach(topic => {
            console.log(`📡 Subscribing to ${topic.path} with handler: ${topic.handler}`);
            const result = this.subscribe(topic.path, topic.handler);
            if (!result) {
                console.error(`Failed to subscribe to ${topic.path}`);
            }
        });
        
        console.log(`📡 Subscription complete. Active subscriptions:`, Array.from(this.subscriptions.keys()));
        console.log(`📡 Total active subscriptions: ${this.subscriptions.size}`);
    }

    /**
     * Subscribe to a specific topic
     * @param {string} topic - The topic path to subscribe to
     * @param {string|Function} handlerNameOrCallback - Handler name for internal routing or callback function
     */
    subscribe(topic, handlerNameOrCallback) {
        if (this.subscriptions.has(topic)) {
            console.log(`📡 Already subscribed to ${topic}`);
            return true;
        }

        if (!this.stompClient || this.connectionState !== 'CONNECTED') {
            console.warn(`Cannot subscribe to ${topic} - not connected`);
            console.warn(`STOMP client: ${this.stompClient ? 'exists' : 'null'}, State: ${this.connectionState}`);
            return false;
        }

        try {
            const subscription = this.stompClient.subscribe(topic, message => {
                console.log(`📨 RAW STOMP message on ${topic}:`, message);
                console.log(`📨 Message headers:`, message.headers);
                console.log(`📨 Message body:`, message.body);
            
            try {
                const data = JSON.parse(message.body);
                console.log(`📨 Parsed message data on ${topic}:`, data);
                
                // Log to UI
                this.logMessage('receive', topic, data);
                
                // Support both callback and event-based handling
                if (typeof handlerNameOrCallback === 'function') {
                    console.log(`📨 Calling callback function for ${topic}`);
                    handlerNameOrCallback(data);
                } else {
                    console.log(`📨 Notifying listeners for event: ${handlerNameOrCallback}`);
                    console.log(`📨 Event name: "${handlerNameOrCallback}"`);
                    console.log(`📨 Data to pass:`, data);
                    this.notifyListeners(handlerNameOrCallback, data);
                }
            } catch (error) {
                console.error(`Error processing message from ${topic}:`, error);
                console.error(`Raw message body was:`, message.body);
            }
            });

            this.subscriptions.set(topic, subscription);
            console.log(`Subscribed to ${topic} with handler:`, handlerNameOrCallback);
            return true;
        } catch (error) {
            console.error(`Error subscribing to ${topic}:`, error);
            return false;
        }
    }

    /**
     * Send message (alias for backward compatibility)
     * @param {string} destination - The destination topic
     * @param {Object} payload - The message payload
     */
    send(destination, payload) {
        return this.sendMessage(destination, payload);
    }

    /**
     * Send message with queuing support
     */
    sendMessage(destination, payload) {
        const message = {
            destination,
            payload,
            timestamp: Date.now()
        };

        if (this.connectionState === 'CONNECTED' && this.stompClient) {
            try {
                this.stompClient.send(destination, {}, JSON.stringify(payload));
                console.log(`📤 Message sent to ${destination}:`, payload);
                this.logMessage('send', destination, payload);
                return true;
            } catch (error) {
                console.error(`Failed to send message to ${destination}:`, error);
                this.queueMessage(message);
                return false;
            }
        } else {
            console.log(`📦 Queuing message for ${destination} (not connected)`);
            this.queueMessage(message);
            return false;
        }
    }

    /**
     * Queue message for later delivery
     */
    queueMessage(message) {
        this.messageQueue.push(message);
        
        // Limit queue size to prevent memory issues
        if (this.messageQueue.length > 100) {
            this.messageQueue.shift(); // Remove oldest message
        }
    }

    /**
     * Flush queued messages after reconnection
     */
    flushMessageQueue() {
        if (this.messageQueue.length === 0) return;

        console.log(`📮 Flushing ${this.messageQueue.length} queued messages`);
        
        const messages = [...this.messageQueue];
        this.messageQueue = [];

        messages.forEach(message => {
            // Skip messages older than 5 minutes
            if (Date.now() - message.timestamp < 300000) {
                this.sendMessage(message.destination, message.payload);
            }
        });
    }

    /**
     * Start heartbeat to keep connection alive
     */
    startHeartbeat() {
        this.stopHeartbeat();
        
        this.heartbeatInterval = setInterval(() => {
            if (this.connectionState === 'CONNECTED') {
                this.sendMessage('/app/heartbeat', { 
                    timestamp: Date.now(),
                    sessionId: window.currentSessionId || 'unknown'
                });
            }
        }, 10000); // Every 10 seconds - 서버와 동기화
    }

    /**
     * Stop heartbeat
     */
    stopHeartbeat() {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
    }

    /**
     * Register event listener
     */
    on(event, callback) {
        if (!this.listeners.has(event)) {
            this.listeners.set(event, []);
        }
        this.listeners.get(event).push(callback);
        
        console.log(`📌 ===========================================`);
        console.log(`📌 EVENT LISTENER REGISTERED`);
        console.log(`📌 Event: "${event}"`);
        console.log(`📌 Total listeners for this event: ${this.listeners.get(event).length}`);
        console.log(`📌 All registered events:`, Array.from(this.listeners.keys()));
        console.log(`📌 ===========================================`);
        
        return () => this.off(event, callback); // Return unsubscribe function
    }

    /**
     * Remove event listener
     */
    off(event, callback) {
        if (this.listeners.has(event)) {
            const callbacks = this.listeners.get(event);
            const index = callbacks.indexOf(callback);
            if (index > -1) {
                callbacks.splice(index, 1);
            }
        }
    }

    /**
     * Emit event (alias for notifyListeners)
     * Added for compatibility and clarity
     */
    emit(event, data) {
        return this.notifyListeners(event, data);
    }
    
    /**
     * Notify all listeners for an event
     */
    notifyListeners(event, data) {
        console.log(`📢 ===========================================`);
        console.log(`📢 EVENT NOTIFICATION: ${event}`);
        console.log(`📢 Data:`, data);
        console.log(`📢 Registered events:`, Array.from(this.listeners.keys()));
        
        if (this.listeners.has(event)) {
            const listeners = this.listeners.get(event);
            console.log(`📢 Found ${listeners.length} listener(s) for "${event}"`);
            
            listeners.forEach((callback, index) => {
                try {
                    console.log(`📢 Executing listener ${index + 1}/${listeners.length} for "${event}"`);
                    callback(data);
                    console.log(`Listener ${index + 1} executed successfully`);
                } catch (error) {
                    console.error(`Error in listener ${index + 1} for "${event}":`, error);
                }
            });
        } else {
            console.warn(`No listeners registered for event: ${event}`);
        }
    }

    /**
     * Wait for connection to be established
     */
    waitForConnection(timeout = 10000) {
        return new Promise((resolve, reject) => {
            const startTime = Date.now();
            
            const checkConnection = () => {
                if (this.connectionState === 'CONNECTED') {
                    resolve();
                } else if (Date.now() - startTime > timeout) {
                    reject(new Error('Connection timeout'));
                } else {
                    setTimeout(checkConnection, 100);
                }
            };
            
            checkConnection();
        });
    }

    /**
     * Disconnect WebSocket
     */
    disconnect() {
        this.isIntentionalDisconnect = true;
        this.stopHeartbeat();

        if (this.stompClient) {
            // Unsubscribe from all topics
            this.subscriptions.forEach((subscription, topic) => {
                subscription.unsubscribe();
                console.log(`📴 Unsubscribed from ${topic}`);
            });
            this.subscriptions.clear();

            // Disconnect STOMP client
            this.stompClient.disconnect(() => {
                console.log('🔌 WebSocket disconnected');
                this.connectionState = 'DISCONNECTED';
                this.notifyListeners('disconnected', {});
                
                // Call onDisconnect callback if defined
                if (typeof this.onDisconnect === 'function') {
                    this.onDisconnect();
                }
            });
            
            this.stompClient = null;
        }
    }

    /**
     * Get current connection state
     */
    getConnectionState() {
        return this.connectionState;
    }

    /**
     * Check if connected
     */
    isConnected() {
        return this.connectionState === 'CONNECTED';
    }

    /**
     * Get queue size
     */
    getQueueSize() {
        return this.messageQueue.length;
    }
    
    /**
     * Log WebSocket messages to UI
     */
    logMessage(direction, topic, data) {
        // Update counters
        const counterId = direction === 'send' ? 'wsSendCount' : 'wsReceiveCount';
        const counterEl = document.getElementById(counterId);
        if (counterEl) {
            const count = parseInt(counterEl.textContent) + 1;
            counterEl.textContent = count;
        }
        
        // Add message to log
        const messagesEl = document.getElementById('websocketMessages');
        if (messagesEl) {
            const timestamp = new Date().toLocaleTimeString('ko-KR', { 
                hour: '2-digit', 
                minute: '2-digit', 
                second: '2-digit',
                fractionalSecondDigits: 3
            });
            
            const messageEl = document.createElement('div');
            messageEl.className = `p-1 rounded ${direction === 'send' ? 'bg-blue-900 bg-opacity-20' : 'bg-green-900 bg-opacity-20'} text-gray-300`;
            
            const icon = direction === 'send' ? '↑' : '↓';
            const color = direction === 'send' ? 'text-blue-400' : 'text-green-400';
            
            messageEl.innerHTML = `
                <span class="${color}">${icon}</span>
                <span class="text-gray-500">[${timestamp}]</span>
                <span class="text-yellow-400">${topic}</span>
                <span class="text-gray-400">:</span>
                <span class="text-gray-300">${this.truncateData(data)}</span>
            `;
            
            // Add to top of log
            messagesEl.insertBefore(messageEl, messagesEl.firstChild);
            
            // Limit log size
            while (messagesEl.children.length > 100) {
                messagesEl.removeChild(messagesEl.lastChild);
            }
        }
    }
    
    /**
     * Truncate data for display
     */
    truncateData(data) {
        const str = typeof data === 'string' ? data : JSON.stringify(data);
        return str.length > 100 ? str.substring(0, 100) + '...' : str;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = EnhancedWebSocketClient;
}

// Make available globally for browser environment
if (typeof window !== 'undefined') {
    window.EnhancedWebSocketClient = EnhancedWebSocketClient;
}