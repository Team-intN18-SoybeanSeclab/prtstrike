(function() {
    function mergeHeaders(extraHeaders) {
        return Object.assign({ 'X-Requested-With': 'XMLHttpRequest' }, extraHeaders || {});
    }

    async function request(url, options) {
        const opts = Object.assign({}, options || {});
        opts.headers = mergeHeaders(opts.headers);
        return fetch(url, opts);
    }

    async function json(url, options) {
        const response = await request(url, options);
        const result = await response.json();
        return { response, result };
    }

    function withJsonBody(method, url, body, options) {
        const opts = Object.assign({}, options || {}, { method: method });
        if (typeof body !== 'undefined') {
            opts.headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
            opts.body = JSON.stringify(body);
        }
        return json(url, opts);
    }

    function apiUrl(path, params) {
        const query = new URLSearchParams();
        Object.entries(params || {}).forEach(function(entry) {
            const key = entry[0];
            const value = entry[1];
            if (value === undefined || value === null || value === '') return;
            query.append(key, value);
        });
        const qs = query.toString();
        return qs ? path + '?' + qs : path;
    }

    function escapeHtml(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function sleep(ms) {
        return new Promise(function(resolve) {
            setTimeout(resolve, ms);
        });
    }

    window.PRTS = window.PRTS || {};
    window.PRTS.api = {
        request: request,
        json: json,
        get: function(url, options) {
            return json(url, options);
        },
        post: function(url, body, options) {
            return withJsonBody('POST', url, body, options);
        },
        put: function(url, body, options) {
            return withJsonBody('PUT', url, body, options);
        },
        delete: function(url, options) {
            return json(url, Object.assign({}, options || {}, { method: 'DELETE' }));
        }
    };
    window.PRTS.apiUrl = apiUrl;
    window.PRTS.escapeHtml = escapeHtml;
    window.PRTS.sleep = sleep;
})();
