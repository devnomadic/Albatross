// Helpers for the URL scan screenshot.
// Browsers block top-level navigation to data: URLs, so "open in new tab" converts the
// data URL into a same-origin blob: URL first.
window.AlbatrossScreenshot = {
    openInNewTab: function (dataUrl) {
        try {
            const [header, base64] = dataUrl.split(',');
            const mime = (/data:([^;]+)/.exec(header) || [])[1] || 'image/jpeg';
            const bytes = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
            const url = URL.createObjectURL(new Blob([bytes], { type: mime }));
            const win = window.open(url, '_blank', 'noopener');
            // Release the blob once the new tab has had time to load it
            setTimeout(() => URL.revokeObjectURL(url), 60000);
            return true;
        } catch (e) {
            console.error('Unable to open screenshot', e);
            return false;
        }
    }
};

// Close the screenshot viewer with Escape
document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
        const overlay = document.querySelector('.screenshot-lightbox');
        if (overlay) overlay.click();
    }
});
