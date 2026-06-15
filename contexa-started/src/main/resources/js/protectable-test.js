(function() {
    'use strict';

    var els = {
        responseStatus: document.getElementById('response-status'),
        responseBody: document.getElementById('response-body'),
        timeline: document.getElementById('timeline')
    };

    function getTimeStr() {
        return new Date().toLocaleTimeString('en-US', { hour12: false });
    }

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function addTimeline(type, msg) {
        var entry = document.createElement('div');
        entry.className = 'timeline-entry ' + type;
        entry.innerHTML =
            '<span class="timeline-time">' + getTimeStr() + '</span>' +
            '<span class="timeline-msg">' + escapeHtml(msg) + '</span>';
        els.timeline.appendChild(entry);
        els.timeline.scrollTop = els.timeline.scrollHeight;
    }

    function getStatusClass(status) {
        if (status >= 200 && status < 300) return 'status-' + status;
        if (status === 401) return 'status-401';
        if (status === 403) return 'status-403';
        if (status === 423) return 'status-423';
        return 'status-500';
    }

    function renderResponse(status, data, elapsed) {
        var timeStr = elapsed !== undefined ? ' <span class="response-time">(' + elapsed + 'ms)</span>' : '';
        els.responseStatus.innerHTML =
            '<span class="response-status ' + getStatusClass(status) + '">HTTP ' + status + '</span>' + timeStr;
        els.responseBody.textContent = JSON.stringify(data, null, 2);
    }

    async function callApi(method, url, body, label) {
        addTimeline('info', label);
        addTimeline('info', method + ' ' + url);

        var start = performance.now();
        var opts = {
            method: method,
            headers: { 'Accept': 'application/json' },
            credentials: 'same-origin'
        };

        if (body) {
            opts.headers['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(body);
        }

        try {
            var response = await fetch(url, opts);
            var elapsed = Math.round(performance.now() - start);

            var data;
            var contentType = response.headers.get('content-type') || '';
            if (contentType.indexOf('application/json') !== -1) {
                try {
                    data = await response.json();
                } catch (e) {
                    data = { raw: 'Non-JSON response', status: response.status };
                }
            } else {
                var text = await response.text();
                data = text ? { raw: text } : { status: response.status, message: 'No content' };
            }

            renderResponse(response.status, data, elapsed);

            if (response.ok) {
                addTimeline('success', 'OK - HTTP ' + response.status + ' (' + elapsed + 'ms)');
            } else if (response.status === 401) {
                addTimeline('warning', 'CHALLENGE - Authentication required (' + elapsed + 'ms)');
            } else if (response.status === 403) {
                addTimeline('error', 'BLOCK - Access denied (' + elapsed + 'ms)');
            } else if (response.status === 423) {
                addTimeline('escalate', 'ESCALATE - Resource locked (' + elapsed + 'ms)');
            } else {
                addTimeline('error', 'Error - HTTP ' + response.status + ' (' + elapsed + 'ms)');
            }
        } catch (err) {
            renderResponse(0, { error: err.message });
            addTimeline('error', 'Network error: ' + err.message);
        }
    }

    function listOrders() {
        callApi('GET', '/api/orders', null, 'Pattern 1: Basic Async - findAll()');
    }

    function listByCustomer() {
        var customerId = document.getElementById('input-customer-id').value || '1';
        callApi('GET', '/api/orders/customer/' + customerId, null,
            'Pattern 2: Async + ownerField - findByCustomer(' + customerId + ')');
    }

    function createOrder() {
        var product = document.getElementById('input-product').value || 'Laptop';
        var quantity = parseInt(document.getElementById('input-quantity').value) || 1;
        var body = { product: product, quantity: quantity };
        callApi('POST', '/api/orders', body, 'Pattern 3: Sync - createOrder()');
    }

    function deleteOrder() {
        var customerId = document.getElementById('input-delete-customer').value || '1';
        var orderId = document.getElementById('input-delete-order').value || '1';
        callApi('DELETE', '/api/orders/' + orderId + '?customerId=' + customerId, null,
            'Pattern 4: Sync + ownerField - deleteOrder(' + customerId + ', ' + orderId + ')');
    }

    window.App = {
        listOrders: listOrders,
        listByCustomer: listByCustomer,
        createOrder: createOrder,
        deleteOrder: deleteOrder
    };
})();
