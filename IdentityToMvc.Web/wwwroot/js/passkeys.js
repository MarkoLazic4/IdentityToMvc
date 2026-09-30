// Passkey (WebAuthn) support for registering passkeys and logging in with them.
// The server produces the options JSON (SignInManager.MakePasskey*OptionsAsync) and verifies the
// JSON-serialized credential the browser returns (PerformPasskeyAttestationAsync / PasskeySignInAsync).
(function () {
    'use strict';

    if (!window.PublicKeyCredential || !navigator.credentials) {
        document.querySelectorAll('[data-passkey-unsupported]').forEach(function (el) { el.hidden = false; });
        document.querySelectorAll('[data-passkey-supported]').forEach(function (el) { el.hidden = true; });
        return;
    }

    var t = window.appText || function (key, fallback) { return fallback; };

    // ---------- base64url helpers ----------
    function toBuffer(base64url) {
        var base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        var padded = base64 + '==='.slice((base64.length + 3) % 4);
        var binary = atob(padded);
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    }

    function toBase64Url(buffer) {
        if (!buffer) return null;
        var bytes = new Uint8Array(buffer);
        var binary = '';
        for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function parseCreationOptions(json) {
        if (PublicKeyCredential.parseCreationOptionsFromJSON) {
            return PublicKeyCredential.parseCreationOptionsFromJSON(json);
        }
        json.challenge = toBuffer(json.challenge);
        json.user.id = toBuffer(json.user.id);
        (json.excludeCredentials || []).forEach(function (c) { c.id = toBuffer(c.id); });
        return json;
    }

    function parseRequestOptions(json) {
        if (PublicKeyCredential.parseRequestOptionsFromJSON) {
            return PublicKeyCredential.parseRequestOptionsFromJSON(json);
        }
        json.challenge = toBuffer(json.challenge);
        (json.allowCredentials || []).forEach(function (c) { c.id = toBuffer(c.id); });
        return json;
    }

    function serialize(credential) {
        if (typeof credential.toJSON === 'function') {
            return JSON.stringify(credential.toJSON());
        }
        var response = credential.response;
        var json = {
            id: credential.id,
            rawId: toBase64Url(credential.rawId),
            type: credential.type,
            authenticatorAttachment: credential.authenticatorAttachment || null,
            clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
            response: { clientDataJSON: toBase64Url(response.clientDataJSON) }
        };
        if (response.attestationObject) {
            json.response.attestationObject = toBase64Url(response.attestationObject);
            json.response.transports = response.getTransports ? response.getTransports() : [];
        } else {
            json.response.authenticatorData = toBase64Url(response.authenticatorData);
            json.response.signature = toBase64Url(response.signature);
            json.response.userHandle = toBase64Url(response.userHandle);
        }
        return JSON.stringify(json);
    }

    // POSTs to an options endpoint with the antiforgery token. If the server redirects
    // (e.g. to "confirm your password"), follow it in the browser instead.
    function fetchOptions(url, form) {
        var token = form.querySelector('input[name="__RequestVerificationToken"]');
        return fetch(url, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'X-XSRF-TOKEN': token ? token.value : '' }
        }).then(function (response) {
            if (response.redirected) {
                window.location.href = response.url;
                return new Promise(function () { });
            }
            if (!response.ok) throw new Error(t('passkeyStart', 'Could not start the passkey request.') + ' (' + response.status + ')');
            return response.json();
        });
    }

    function showError(container, message) {
        if (!container) return;
        container.textContent = message;
        container.hidden = false;
    }

    function friendlyError(error) {
        if (error && error.name === 'NotAllowedError') return t('passkeyCancelled', 'The passkey request was cancelled or timed out.');
        if (error && error.name === 'InvalidStateError') return t('passkeyExists', 'This device already has a passkey for your account.');
        return (error && error.message) || t('passkeyFailed', 'Something went wrong with the passkey request.');
    }

    // ---------- Register a passkey (Manage > Passkeys) ----------
    var addForm = document.getElementById('add-passkey-form');
    if (addForm) {
        addForm.addEventListener('submit', function (event) {
            if (addForm.dataset.ready === 'true') return; // second pass: real submit
            event.preventDefault();
            var error = document.getElementById('passkey-error');
            var button = addForm.querySelector('button[type="submit"]');
            button.disabled = true;

            fetchOptions(addForm.getAttribute('data-options-url'), addForm)
                .then(function (json) { return navigator.credentials.create({ publicKey: parseCreationOptions(json) }); })
                .then(function (credential) {
                    addForm.querySelector('input[name="credentialJson"]').value = serialize(credential);
                    addForm.dataset.ready = 'true';
                    addForm.submit();
                })
                .catch(function (e) {
                    button.disabled = false;
                    showError(error, friendlyError(e));
                });
        });
    }

    // ---------- Log in with a passkey ----------
    var loginForm = document.getElementById('passkey-login-form');
    if (loginForm) {
        var error = document.getElementById('passkey-login-error');
        var conditionalAbort = null;

        var submitAssertion = function (credential) {
            loginForm.querySelector('input[name="credentialJson"]').value = serialize(credential);
            loginForm.submit();
        };

        var start = function (mediation) {
            if (conditionalAbort) conditionalAbort.abort();
            var abort = new AbortController();
            if (mediation === 'conditional') conditionalAbort = abort;

            return fetchOptions(loginForm.getAttribute('data-options-url'), loginForm)
                .then(function (json) {
                    var request = { publicKey: parseRequestOptions(json), signal: abort.signal };
                    if (mediation) request.mediation = mediation;
                    return navigator.credentials.get(request);
                })
                .then(function (credential) { if (credential) submitAssertion(credential); });
        };

        var button = document.getElementById('passkey-login-button');
        if (button) {
            button.addEventListener('click', function () {
                start(null).catch(function (e) {
                    if (e && e.name === 'AbortError') return;
                    showError(error, friendlyError(e));
                });
            });
        }

        // Passkey autofill: offer passkeys in the email field's autocomplete dropdown
        if (PublicKeyCredential.isConditionalMediationAvailable) {
            PublicKeyCredential.isConditionalMediationAvailable().then(function (available) {
                if (available) start('conditional').catch(function () { /* user ignored autofill */ });
            });
        }
    }
})();
