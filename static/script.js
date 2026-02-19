document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'f') {
        e.preventDefault();
        window.open('/search', '_blank');
    }
});

let events = [], links = [];
let graphNetwork, timeline;

// Drag and drop UI handling
const dropArea = document.getElementById('drop-area');
const fileInput = document.getElementById('file-input');
const fileNameDisplay = document.getElementById('file-name');

['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropArea.addEventListener(eventName, preventDefaults, false);
});

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

['dragenter', 'dragover'].forEach(eventName => {
    dropArea.addEventListener(eventName, () => dropArea.classList.add('highlight'), false);
});

['dragleave', 'drop'].forEach(eventName => {
    dropArea.addEventListener(eventName, () => dropArea.classList.remove('highlight'), false);
});

dropArea.addEventListener('drop', handleDrop, false);

function handleDrop(e) {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length) {
        fileInput.files = files;
        updateFileName(files[0].name);
    }
}

fileInput.addEventListener('change', function() {
    if (this.files.length) {
        updateFileName(this.files[0].name);
    }
});

function updateFileName(name) {
    fileNameDisplay.textContent = 'Selected: ' + name;
    fileNameDisplay.style.color = '#4caf50';
    fileNameDisplay.style.fontWeight = 'bold';
}

document.getElementById('upload-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    // Re-select fileInput here just to be safe, though declared above.
    const file = fileInput.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    const loading = document.getElementById('loading');
    const dashboard = document.getElementById('dashboard');
    loading.style.display = 'block';
    dashboard.style.display = 'none';

    try {
        const response = await fetch('/upload', {
            method: 'POST',
            body: formData
        });
        const data = await response.json();
        if (data.error) {
            let msg = 'Error: ' + data.error;
            if (data.details) msg += '\n\n' + data.details;
            alert(msg);
            return;
        }
        events = data.events;
        links = data.links;
        try {
            localStorage.setItem('events', JSON.stringify(events));
            localStorage.setItem('links', JSON.stringify(links));
        } catch (err) {
            console.warn('Failed to cache timeline data:', err);
        }
        renderDashboard();
        dashboard.style.display = 'block';
    } catch (err) {
        alert('Upload failed: ' + err);
    } finally {
        loading.style.display = 'none';
    }
});

function renderDashboard() {
    const nodes = events.map(e => ({
        id: e.id,
        label: `${e.type}\n${truncate(e.description, 30)}`,
        title: e.description,
        group: e.type,
        details: e
    }));

    const edges = links.map(l => ({
        from: l.source,
        to: l.target,
        label: l.label,
        arrows: 'to',
        font: { align: 'middle', color: '#b0bec5' },
        color: { color: '#7f8c8d', highlight: '#e67e22' }
    }));

    const groups = {
        'TCP Connection': { color: { background: '#3498db', border: '#2980b9' } },
        'DNS Query': { color: { background: '#2ecc71', border: '#27ae60' } },
        'DNS Response': { color: { background: '#2ecc71', border: '#27ae60' } },
        'HTTP Request': { color: { background: '#e74c3c', border: '#c0392b' } },
        'HTTP Response': { color: { background: '#e67e22', border: '#d35400' } },
        'TLS SNI': { color: { background: '#9b59b6', border: '#8e44ad' } },
        'ICMP': { color: { background: '#f1c40f', border: '#f39c12' } },
        'ARP': { color: { background: '#1abc9c', border: '#16a085' } }
    };

    const container = document.getElementById('graph');
    const graphData = { nodes, edges };
    const options = {
        layout: { hierarchical: false },
        nodes: {
            shape: 'box',
            margin: 10,
            widthConstraint: { maximum: 200 },
            font: { color: '#ecf0f1' }
        },
        edges: { smooth: true },
        groups: groups,
        interaction: { hover: true, navigationButtons: true },
        physics: { enabled: true }
    };
    graphNetwork = new vis.Network(container, graphData, options);

    graphNetwork.on('click', function(params) {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            const event = events.find(e => e.id === nodeId);
            if (event) showDetails(event);
        }
    });

    const timelineContainer = document.getElementById('timeline');
    const timelineItems = new vis.DataSet(
        events.map(e => ({
            id: e.id,
            content: `${e.type}: ${truncate(e.description, 50)}`,
            start: new Date(e.timestamp * 1000),
            group: e.type,
            className: `timeline-${e.type.replace(' ', '-')}`
        }))
    );
    const timelineGroups = new vis.DataSet(
        [...new Set(events.map(e => e.type))].map(type => ({ id: type, content: type }))
    );
    const timelineOptions = {
        stack: true,
        showCurrentTime: true,
        height: '100%',
        groupOrder: 'content',
        editable: false,
        selectable: true,
        multiselect: false,
        tooltip: { followMouse: true }
    };
    timeline = new vis.Timeline(timelineContainer, timelineItems, timelineGroups, timelineOptions);
    timeline.on('select', function(props) {
        if (props.items.length > 0) {
            const eventId = props.items[0];
            const event = events.find(e => e.id === eventId);
            if (event) {
                graphNetwork.selectNodes([eventId]);
                showDetails(event);
            }
        }
    });
}

function truncate(str, len) {
    if (str.length <= len) return str;
    return str.substr(0, len) + '…';
}

function showDetails(event) {
    const pre = document.getElementById('details-content');
    pre.innerHTML = syntaxHighlight(JSON.stringify(event, null, 2));
}

function syntaxHighlight(json) {
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
        let cls = 'number';
        if (/^"/.test(match)) {
            if (/:$/.test(match)) {
                cls = 'key';
            } else {
                cls = 'string';
            }
        } else if (/true|false/.test(match)) {
            cls = 'boolean';
        } else if (/null/.test(match)) {
            cls = 'null';
        }
        return '<span class="' + cls + '">' + match + '</span>';
    });
}
