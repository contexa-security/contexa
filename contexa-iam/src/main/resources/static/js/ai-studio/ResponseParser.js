/**
 * ResponseParser - JSON Response Parsing Utility
 * Handles parsing and validation of streaming response data
 */
class ResponseParser {
    constructor() {
        this.markers = AIStudioConfig.markers;
    }

    /**
     * Parses the final response from streaming data
     * @param {string} data - The raw response data
     * @returns {Object|null} Parsed response or null
     */
    parseFinalResponse(data) {
        if (!data) {
            return null;
        }

        try {
            if (data.includes(this.markers.FINAL_RESPONSE)) {
                const markerIndex = data.indexOf(this.markers.FINAL_RESPONSE);
                const jsonString = data.substring(markerIndex + this.markers.FINAL_RESPONSE.length);
                return this.parseJson(jsonString);
            }

            return this.parseJson(data);
        } catch (error) {
            console.error('Failed to parse final response:', error);
            return this.createErrorResponse(data, error);
        }
    }

    /**
     * Parses JSON string with error handling
     * @param {string} jsonString - The JSON string to parse
     * @returns {Object} Parsed JSON object
     */
    parseJson(jsonString) {
        if (!jsonString || typeof jsonString !== 'string') {
            throw new Error('Invalid JSON input');
        }

        const trimmed = jsonString.trim();
        if (!trimmed) {
            throw new Error('Empty JSON input');
        }

        return JSON.parse(trimmed);
    }

    /**
     * Extracts JSON from marked content
     * @param {string} data - Data containing JSON markers
     * @param {string} startMarker - Start marker
     * @param {string} endMarker - End marker
     * @returns {Object|null} Parsed JSON or null
     */
    extractMarkedJson(data, startMarker, endMarker) {
        if (!data || !data.includes(startMarker)) {
            return null;
        }

        try {
            const startIndex = data.indexOf(startMarker) + startMarker.length;
            const endIndex = endMarker ? data.indexOf(endMarker, startIndex) : data.length;

            if (endIndex === -1) {
                return null;
            }

            const jsonString = data.substring(startIndex, endIndex);
            return this.parseJson(jsonString);
        } catch (error) {
            console.error('Failed to extract marked JSON:', error);
            return null;
        }
    }

    /**
     * Validates if a string is valid JSON
     * @param {string} str - String to validate
     * @returns {boolean} True if valid JSON
     */
    isValidJson(str) {
        if (!str || typeof str !== 'string') {
            return false;
        }

        try {
            JSON.parse(str.trim());
            return true;
        } catch (error) {
            return false;
        }
    }

    /**
     * Extracts error information from response
     * @param {Object|string} response - The response to check
     * @returns {Object|null} Error info or null
     */
    extractError(response) {
        if (!response) {
            return null;
        }

        if (typeof response === 'string') {
            try {
                response = JSON.parse(response);
            } catch (error) {
                return null;
            }
        }

        if (response.error) {
            return {
                code: response.error.code || 'UNKNOWN_ERROR',
                message: response.error.message || 'Unknown error occurred'
            };
        }

        return null;
    }

    /**
     * Creates an error response object
     * @param {string} rawData - The raw data that failed to parse
     * @param {Error} error - The parsing error
     * @returns {Object} Error response object
     */
    createErrorResponse(rawData, error) {
        return {
            parseError: true,
            raw: rawData,
            errorMessage: error.message
        };
    }

    /**
     * Checks if response contains final marker
     * @param {string} data - Data to check
     * @returns {boolean} True if contains final marker
     */
    hasFinalMarker(data) {
        return data && data.includes(this.markers.FINAL_RESPONSE);
    }

    /**
     * Checks if response contains done marker
     * @param {string} data - Data to check
     * @returns {boolean} True if contains done marker
     */
    isDone(data) {
        return data === this.markers.DONE;
    }

    /**
     * Sanitizes JSON string by removing problematic characters
     * @param {string} jsonString - The JSON string to sanitize
     * @returns {string} Sanitized JSON string
     */
    sanitizeJson(jsonString) {
        if (!jsonString || typeof jsonString !== 'string') {
            return jsonString;
        }

        return jsonString
            .replace(/[\x00-\x1F\x7F]/g, '')
            .trim();
    }

    /**
     * Merges multiple JSON responses
     * @param {Array<Object>} responses - Array of response objects
     * @returns {Object} Merged response
     */
    mergeResponses(responses) {
        if (!Array.isArray(responses) || responses.length === 0) {
            return null;
        }

        return responses.reduce((merged, response) => {
            if (response && typeof response === 'object' && !response.parseError) {
                return { ...merged, ...response };
            }
            return merged;
        }, {});
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = ResponseParser;
}
