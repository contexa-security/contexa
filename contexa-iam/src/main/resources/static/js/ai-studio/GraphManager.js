/**
 * GraphManager - Cytoscape.js Graph Management
 * Handles graph initialization, data management, and visualization
 */
class GraphManager {
    constructor(containerId) {
        this.containerId = containerId;
        this.cy = null;
        this.initPromise = null;
        this.isInitialized = false;
    }

    /**
     * Initializes the Cytoscape instance
     * @returns {Promise<boolean>}
     */
    async initialize() {
        if (this.initPromise) {
            return this.initPromise;
        }

        this.initPromise = new Promise(async (resolve, reject) => {
            try {
                await this.waitForCytoscape();
                this.cy = this.createInstance();
                this.isInitialized = true;
                resolve(true);
            } catch (error) {
                this.isInitialized = false;
                reject(error);
            }
        });

        return this.initPromise;
    }

    /**
     * Waits for Cytoscape library to be loaded
     * @returns {Promise<void>}
     */
    waitForCytoscape() {
        return new Promise((resolve, reject) => {
            if (typeof cytoscape !== 'undefined') {
                resolve();
                return;
            }

            const startTime = Date.now();
            const timeout = AIStudioConfig.timing.CYTOSCAPE_LOAD_TIMEOUT;
            const interval = AIStudioConfig.timing.CYTOSCAPE_LOAD_CHECK_INTERVAL;

            const checkInterval = setInterval(() => {
                if (typeof cytoscape !== 'undefined') {
                    clearInterval(checkInterval);
                    resolve();
                } else if (Date.now() - startTime > timeout) {
                    clearInterval(checkInterval);
                    reject(new Error('Cytoscape load timeout'));
                }
            }, interval);
        });
    }

    /**
     * Creates the Cytoscape instance
     * @returns {Object} Cytoscape instance
     */
    createInstance() {
        const container = document.getElementById(this.containerId);
        if (!container) {
            throw new Error(`Container #${this.containerId} not found`);
        }

        return cytoscape({
            container: container,
            style: this.getDefaultStyle(),
            layout: { name: 'preset' },
            minZoom: 0.3,
            maxZoom: 3,
            wheelSensitivity: 0.3
        });
    }

    /**
     * Gets the default Cytoscape style
     * @returns {Array} Style configuration
     */
    getDefaultStyle() {
        return [
            {
                selector: 'node',
                style: {
                    'label': 'data(label)',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'background-color': '#4a90d9',
                    'color': '#fff',
                    'font-size': '12px',
                    'text-wrap': 'wrap',
                    'text-max-width': '100px',
                    'width': 'label',
                    'height': 'label',
                    'padding': '10px',
                    'shape': 'roundrectangle'
                }
            },
            {
                selector: 'node[type="user"]',
                style: {
                    'background-color': '#5cb85c',
                    'shape': 'ellipse'
                }
            },
            {
                selector: 'node[type="role"]',
                style: {
                    'background-color': '#f0ad4e',
                    'shape': 'diamond'
                }
            },
            {
                selector: 'node[type="permission"]',
                style: {
                    'background-color': '#d9534f',
                    'shape': 'rectangle'
                }
            },
            {
                selector: 'node[type="resource"]',
                style: {
                    'background-color': '#5bc0de',
                    'shape': 'hexagon'
                }
            },
            {
                selector: 'edge',
                style: {
                    'curve-style': 'bezier',
                    'target-arrow-shape': 'triangle',
                    'target-arrow-color': '#999',
                    'line-color': '#999',
                    'width': 2,
                    'label': 'data(label)',
                    'font-size': '10px',
                    'text-rotation': 'autorotate'
                }
            },
            {
                selector: ':selected',
                style: {
                    'border-width': 3,
                    'border-color': '#333'
                }
            }
        ];
    }

    /**
     * Sets the graph data
     * @param {Object} data - Graph data with nodes and edges
     */
    setData(data) {
        if (!this.cy) {
            console.error('GraphManager not initialized');
            return;
        }

        this.cy.elements().remove();

        if (data.nodes && Array.isArray(data.nodes)) {
            this.cy.add(data.nodes.map(node => ({
                group: 'nodes',
                data: node.data || node
            })));
        }

        if (data.edges && Array.isArray(data.edges)) {
            this.cy.add(data.edges.map(edge => ({
                group: 'edges',
                data: edge.data || edge
            })));
        }

        this.applyLayout();
    }

    /**
     * Applies the layout to the graph
     * @param {string} layoutName - Layout algorithm name
     * @param {Object} options - Layout options
     */
    applyLayout(layoutName = 'cose', options = {}) {
        if (!this.cy) {
            return;
        }

        const defaultOptions = {
            name: layoutName,
            animate: true,
            animationDuration: 500,
            fit: true,
            padding: 50
        };

        const layout = this.cy.layout({
            ...defaultOptions,
            ...options
        });

        layout.run();
    }

    /**
     * Fits the graph to the viewport
     * @param {number} padding - Padding around the graph
     */
    fit(padding = 50) {
        if (this.cy) {
            this.cy.fit(padding);
        }
    }

    /**
     * Centers the graph
     */
    center() {
        if (this.cy) {
            this.cy.center();
        }
    }

    /**
     * Zooms to a specific level
     * @param {number} level - Zoom level
     */
    zoom(level) {
        if (this.cy) {
            this.cy.zoom(level);
        }
    }

    /**
     * Highlights a node by ID
     * @param {string} nodeId - The node ID to highlight
     */
    highlightNode(nodeId) {
        if (!this.cy) {
            return;
        }

        this.cy.nodes().removeClass('highlighted');
        const node = this.cy.getElementById(nodeId);
        if (node) {
            node.addClass('highlighted');
            this.cy.animate({
                center: { eles: node },
                duration: 300
            });
        }
    }

    /**
     * Clears all highlights
     */
    clearHighlights() {
        if (this.cy) {
            this.cy.elements().removeClass('highlighted');
        }
    }

    /**
     * Registers an event handler
     * @param {string} event - Event name
     * @param {string} selector - Element selector
     * @param {Function} handler - Event handler function
     */
    on(event, selector, handler) {
        if (this.cy) {
            if (typeof selector === 'function') {
                this.cy.on(event, selector);
            } else {
                this.cy.on(event, selector, handler);
            }
        }
    }

    /**
     * Removes an event handler
     * @param {string} event - Event name
     * @param {string} selector - Element selector
     * @param {Function} handler - Event handler function
     */
    off(event, selector, handler) {
        if (this.cy) {
            if (typeof selector === 'function') {
                this.cy.off(event, selector);
            } else {
                this.cy.off(event, selector, handler);
            }
        }
    }

    /**
     * Exports the graph as PNG
     * @returns {string} Base64 encoded PNG
     */
    exportPng() {
        if (this.cy) {
            return this.cy.png({
                bg: '#ffffff',
                full: true,
                scale: 2
            });
        }
        return null;
    }

    /**
     * Exports the graph data as JSON
     * @returns {Object} Graph data
     */
    exportJson() {
        if (this.cy) {
            return this.cy.json();
        }
        return null;
    }

    /**
     * Resizes the graph to fit the container
     */
    resize() {
        if (this.cy) {
            this.cy.resize();
            this.cy.fit();
        }
    }

    /**
     * Destroys the graph instance
     */
    destroy() {
        if (this.cy) {
            this.cy.destroy();
            this.cy = null;
        }
        this.initPromise = null;
        this.isInitialized = false;
    }

    /**
     * Checks if the graph is initialized
     * @returns {boolean}
     */
    isReady() {
        return this.isInitialized && this.cy !== null;
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = GraphManager;
}
