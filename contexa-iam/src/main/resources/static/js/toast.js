function showToast(message, type = 'info', duration = 3000) {
    const container = document.getElementById('toast-container');
    if (!container) {
        console.warn('Toast container not found. Using alert instead.');
        alert(`${type.toUpperCase()}: ${message}`);
        return;
    }

    const toast = document.createElement('div');
    let bgColorClass = 'bg-info';
    if (type === 'success') {
        bgColorClass = 'bg-success';
    } else if (type === 'error') {
        bgColorClass = 'bg-error';
    }

    toast.className = `p-4 mb-2 rounded-md shadow-lg text-white text-sm ${bgColorClass} transition-opacity duration-500 ease-out`;
    toast.textContent = message;

    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('opacity-0');
        setTimeout(() => {
            toast.remove();
        }, 500);
    }, duration);
}
