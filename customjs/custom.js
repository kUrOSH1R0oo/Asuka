console.log('Custom JS: Tracking user interactions');
document.addEventListener('click', function(e) {
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/track', true);
    xhr.send('type=click&x=' + e.clientX + '&y=' + e.clientY + '&target=' + encodeURIComponent(e.target.tagName));
});
document.addEventListener('mousemove', function(e) {
    if (Math.random() < 0.1) {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/track', true);
        xhr.send('type=mousemove&x=' + e.clientX + '&y=' + e.clientY);
    }
});
