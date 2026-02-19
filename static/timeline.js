let events = [];
let timeline;

function loadTimelineData() {
    try {
        const stored = localStorage.getItem('events');
        if (stored) {
            events = JSON.parse(stored);
        }
    } catch (err) {
        console.warn('Failed to read timeline data:', err);
    }
}

function renderTimeline() {
    const emptyState = document.getElementById('timeline-empty');
    const dashboard = document.getElementById('timeline-dashboard');

    if (!events || events.length === 0) {
        emptyState.style.display = 'block';
        dashboard.style.display = 'none';
        return;
    }

    const timelineContainer = document.getElementById('timeline');
    const timelineItems = new vis.DataSet(
        events.map(e => ({
            id: e.id,
            content: `${e.type}: ${truncate(e.description, 60)}`,
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
    timeline.on('select', function (props) {
        if (props.items.length > 0) {
            const eventId = props.items[0];
            const event = events.find(e => e.id === eventId);
            if (event) showDetails(event);
        }
    });
}

function truncate(str, len) {
    if (!str) return '';
    if (str.length <= len) return str;
    return str.substr(0, len) + '...';
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

loadTimelineData();
renderTimeline();
