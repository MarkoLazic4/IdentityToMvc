// Renders the authenticator QR code on the "Configure authenticator app" page.
(function () {
    'use strict';
    var data = document.getElementById('qrCodeData');
    var target = document.getElementById('qrCode');
    if (!data || !target || typeof QRCode === 'undefined') return;
    new QRCode(target, { text: data.getAttribute('data-url'), width: 160, height: 160 });
})();
