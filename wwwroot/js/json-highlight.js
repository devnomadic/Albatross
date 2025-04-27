// Function to highlight JSON code
window.highlightJson = function() {
    const codeBlock = document.getElementById('jsonOutput');
    if (codeBlock) {
        // Check if content is already highlighted
        if (!codeBlock.classList.contains('hljs')) {
            // Apply the 'language-json' class for highlighting
            codeBlock.className = 'bg-dark text-light p-3 rounded json-output language-json';
            // Run the highlighter
            hljs.highlightElement(codeBlock);
        }
    }
}; 