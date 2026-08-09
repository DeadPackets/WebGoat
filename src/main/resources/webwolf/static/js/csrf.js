/*
 * The server rejects a state changing request that does not carry the CSRF token, so every request
 * this page makes to WebWolf itself repeats the token from the cookie.
 */
(function () {
    var open = XMLHttpRequest.prototype.open;
    var send = XMLHttpRequest.prototype.send;

    function needsToken(method, url) {
        if (/^(GET|HEAD|OPTIONS|TRACE)$/.test(String(method).toUpperCase())) {
            return false;
        }
        try {
            return new URL(url, window.location.href).origin === window.location.origin;
        } catch (e) {
            return false;
        }
    }

    function csrfToken() {
        var match = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]*)/);
        return match ? decodeURIComponent(match[1]) : null;
    }

    XMLHttpRequest.prototype.open = function (method, url) {
        this._needsCsrfToken = needsToken(method, url);
        return open.apply(this, arguments);
    };

    XMLHttpRequest.prototype.send = function () {
        var token = csrfToken();
        if (this._needsCsrfToken && token) {
            this.setRequestHeader('X-XSRF-TOKEN', token);
        }
        return send.apply(this, arguments);
    };
})();
