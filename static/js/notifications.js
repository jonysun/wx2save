(function () {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/notifications`;
    let socket;

    function connect() {
        socket = new WebSocket(wsUrl);

        socket.onmessage = function (event) {
            if (event.data === 'new_message') {
                showNotification();
            }
        };

        socket.onclose = function (e) {
            console.log('Socket closed. Reconnecting in 3s...');
            setTimeout(connect, 3000); // Reconnect
        };
    }

    function showNotification() {
        // 移除旧的通知
        const oldToast = document.getElementById('liveToastContainer');
        if (oldToast) oldToast.remove();

        let countdown = 5;
        const toastHtml = `
            <div id="liveToastContainer" class="position-fixed bottom-0 end-0 p-3" style="z-index: 1100">
                <div id="liveToast" class="toast show text-white bg-primary" role="alert" aria-live="assertive" aria-atomic="true">
                    <div class="d-flex">
                        <div class="toast-body">
                            <i class="bi bi-bell-fill me-2"></i> 收到新消息！
                            <span id="countdown" class="fw-bold ms-2">${countdown}秒后自动刷新</span>
                            <a href="javascript:location.reload()" class="text-white fw-bold ms-2 text-decoration-underline">立即刷新</a>
                        </div>
                        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close" onclick="this.closest('#liveToastContainer').remove()"></button>
                    </div>
                </div>
            </div>
        `;

        const div = document.createElement('div');
        div.innerHTML = toastHtml;
        document.body.appendChild(div.firstElementChild);

        // 倒计时
        const countdownEl = document.getElementById('countdown');
        const interval = setInterval(() => {
            countdown--;
            if (countdownEl) {
                countdownEl.innerText = `${countdown}秒后自动刷新`;
            }
            if (countdown <= 0) {
                clearInterval(interval);
                location.reload();
            }
        }, 1000);

        // 如果用户关闭通知，取消自动刷新
        const toast = document.getElementById('liveToastContainer');
        if (toast) {
            toast.addEventListener('hidden.bs.toast', () => {
                clearInterval(interval);
            });
        }
    }

    connect();
})();
