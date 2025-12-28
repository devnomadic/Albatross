// Function to highlight JSON code
window.highlightJson = function() {
    // Check if highlight.js is available
    if (typeof hljs === 'undefined') {
        console.warn('highlight.js not available yet');
        return;
    }
    
    const codeBlock = document.getElementById('jsonOutput');
    if (codeBlock) {
        // Check if content is already highlighted
        if (!codeBlock.classList.contains('hljs')) {
            try {
                // Sanitize content by using textContent to prevent HTML injection
                const jsonText = codeBlock.textContent;
                codeBlock.textContent = jsonText;
                
                // Apply the 'language-json' class for highlighting
                codeBlock.className = 'bg-dark text-light p-3 rounded json-output language-json';
                // Run the highlighter
                hljs.highlightElement(codeBlock);
                console.log('JSON highlighting applied successfully');
            } catch (error) {
                console.error('Error applying JSON highlighting:', error);
            }
        }
    }
}; 