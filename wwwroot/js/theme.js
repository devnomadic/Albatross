// Dark/light theme persistence, shared between the early inline bootstrap script
// (in index.html, which avoids a flash of the wrong theme) and Blazor.
window.albatrossTheme = {
    STORAGE_KEY: 'albatross-theme',

    getTheme: function () {
        const stored = localStorage.getItem(this.STORAGE_KEY);
        if (stored === 'dark' || stored === 'light') {
            return stored;
        }
        return (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
    },

    setTheme: function (theme) {
        const normalized = theme === 'dark' ? 'dark' : 'light';
        localStorage.setItem(this.STORAGE_KEY, normalized);
        document.documentElement.setAttribute('data-theme', normalized);
    }
};
