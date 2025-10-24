// resources/static/js/toast.js (개선 예시)
function showToast(message, type = 'info', duration = 3000) {
    const container = document.getElementById('toast-container');
    if (!container) {
        console.warn('Toast container not found. Using alert instead.');
        alert(`${type.toUpperCase()}: ${message}`);
        return;
    }

    const toast = document.createElement('div');
    let bgColorClass = 'bg-info'; // 기본 info
    if (type === 'success') {
        bgColorClass = 'bg-success';
    } else if (type === 'error') {
        bgColorClass = 'bg-error';
    }
    // app-primary, app-accent 등 tailwind.config.js에 정의된 색상 사용 가능
    // else if (type === 'primary') {
    //     bgColorClass = 'bg-app-primary';
    // }

    toast.className = `p-4 mb-2 rounded-md shadow-lg text-white text-sm ${bgColorClass} transition-opacity duration-500 ease-out`;
    toast.textContent = message;

    container.appendChild(toast);

    // Fade out
    setTimeout(() => {
        toast.classList.add('opacity-0');
        setTimeout(() => {
            toast.remove();
        }, 500); // 애니메이션 시간 후 제거
    }, duration);
}
