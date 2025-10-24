// admin-menu.js - 현재 페이지 활성화 표시
document.addEventListener('DOMContentLoaded', function() {
    const currentPath = window.location.pathname;
    const menuLinks = document.querySelectorAll('.admin-sidebar a');

    menuLinks.forEach(link => {
        const href = link.getAttribute('href');

        // 정확히 일치하는 경로
        if (href === currentPath) {
            link.classList.add('active');
        }
        // 하위 경로 포함 (예: /admin/users/new는 /admin/users 메뉴 활성화)
        else if (currentPath.startsWith(href) && href !== '/admin/dashboard') {
            link.classList.add('active');
        }
    });

    // 대시보드는 정확히 일치할 때만 활성화
    if (currentPath === '/admin/dashboard' || currentPath === '/admin') {
        const dashboardLink = document.querySelector('a[href*="/admin/dashboard"]');
        if (dashboardLink) {
            dashboardLink.classList.add('active');
        }
    }
});