document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'f') {
        e.preventDefault();
        window.open('/search', '_blank');
    }
    if (e.ctrlKey && e.key === 'k') {
        e.preventDefault();
        window.open('/search', '_blank');
    }
});
