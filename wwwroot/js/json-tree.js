// Renders an interactive, collapsible JSON tree (similar to an IDE's object/outline
// viewer) into a target container. Each object/array node gets a toggle arrow that
// can be clicked to collapse/expand just that node, independent of its siblings.
(function () {
    function escapeHtml(str) {
        return str.replace(/[&<>"']/g, function (ch) {
            switch (ch) {
                case '&': return '&amp;';
                case '<': return '&lt;';
                case '>': return '&gt;';
                case '"': return '&quot;';
                case "'": return '&#39;';
                default: return ch;
            }
        });
    }

    function valueSpan(value) {
        if (value === null) {
            return '<span class="json-null">null</span>';
        }
        switch (typeof value) {
            case 'string':
                return '<span class="json-string">"' + escapeHtml(value) + '"</span>';
            case 'number':
                return '<span class="json-number">' + value + '</span>';
            case 'boolean':
                return '<span class="json-boolean">' + value + '</span>';
            default:
                return '<span class="json-value">' + escapeHtml(String(value)) + '</span>';
        }
    }

    function keySpanHtml(key) {
        return key !== null ? '<span class="json-key">"' + escapeHtml(String(key)) + '"</span><span class="json-colon">: </span>' : '';
    }

    function buildNode(key, value) {
        const li = document.createElement('li');
        li.className = 'json-tree-node';

        const isArray = Array.isArray(value);
        const isObject = value !== null && typeof value === 'object' && !isArray;
        const isContainer = isObject || isArray;

        const row = document.createElement('div');
        row.className = 'json-tree-row';
        li.appendChild(row);

        if (isContainer) {
            const entries = isArray ? value.map((v, i) => [i, v]) : Object.entries(value);
            const hasChildren = entries.length > 0;

            const toggle = document.createElement('span');
            toggle.className = 'json-toggle' + (hasChildren ? '' : ' json-toggle-empty');
            toggle.textContent = hasChildren ? '▼' : '';
            row.appendChild(toggle);

            const keyEl = document.createElement('span');
            keyEl.innerHTML = keySpanHtml(key);
            row.appendChild(keyEl);

            const bracketOpen = document.createElement('span');
            bracketOpen.className = 'json-bracket';
            bracketOpen.textContent = isArray ? '[' : '{';
            row.appendChild(bracketOpen);

            const summary = document.createElement('span');
            summary.className = 'json-summary';
            summary.textContent = entries.length + (isArray
                ? (entries.length === 1 ? ' item' : ' items')
                : (entries.length === 1 ? ' key' : ' keys'));
            row.appendChild(summary);

            if (!hasChildren) {
                const bracketCloseInline = document.createElement('span');
                bracketCloseInline.className = 'json-bracket';
                bracketCloseInline.textContent = isArray ? ']' : '}';
                row.appendChild(bracketCloseInline);
                return li;
            }

            const childList = document.createElement('ul');
            childList.className = 'json-tree-children';
            entries.forEach(([k, v]) => {
                childList.appendChild(buildNode(isArray ? null : k, v));
            });
            li.appendChild(childList);

            const bracketClose = document.createElement('div');
            bracketClose.className = 'json-bracket json-bracket-close';
            bracketClose.textContent = isArray ? ']' : '}';
            li.appendChild(bracketClose);

            row.addEventListener('click', function (e) {
                e.stopPropagation();
                const collapsed = li.classList.toggle('json-collapsed');
                toggle.textContent = collapsed ? '▶' : '▼';
            });
        } else {
            const keyEl = document.createElement('span');
            keyEl.innerHTML = keySpanHtml(key);
            row.appendChild(keyEl);

            const val = document.createElement('span');
            val.innerHTML = valueSpan(value);
            row.appendChild(val);
        }

        return li;
    }

    // Parses jsonString and renders a collapsible tree into the element with id containerId.
    window.renderJsonTree = function (containerId, jsonString) {
        const container = document.getElementById(containerId);
        if (!container) return;

        let data;
        try {
            data = JSON.parse(jsonString);
        } catch (error) {
            console.error('renderJsonTree: invalid JSON', error);
            container.textContent = jsonString;
            return;
        }

        container.innerHTML = '';
        const root = document.createElement('ul');
        root.className = 'json-tree-root';
        root.appendChild(buildNode(null, data));
        container.appendChild(root);
    };

    // Expands or collapses every node in the tree at once.
    window.jsonTreeSetAllCollapsed = function (containerId, collapsed) {
        const container = document.getElementById(containerId);
        if (!container) return;
        container.querySelectorAll('.json-tree-node').forEach(function (li) {
            const toggle = li.querySelector(':scope > .json-tree-row > .json-toggle');
            if (!toggle || toggle.classList.contains('json-toggle-empty')) return;
            li.classList.toggle('json-collapsed', collapsed);
            toggle.textContent = collapsed ? '▶' : '▼';
        });
    };
})();
