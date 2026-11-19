package httpapi

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const adminLoginPath = "/api/v1/media/admin/login"

func (a *Admin) canShowLogin(c *gin.Context) bool {
	return a.settings.TLSEnabled && a.directManagementOrigin(c)
}

func adminPageNavigation(c *gin.Context) bool {
	if mode := c.GetHeader("Sec-Fetch-Mode"); mode != "" && mode != "navigate" {
		return false
	}
	for _, value := range strings.Split(c.GetHeader("Accept"), ",") {
		mediaType, _, _ := strings.Cut(value, ";")
		if strings.EqualFold(strings.TrimSpace(mediaType), "text/html") {
			return true
		}
	}
	return false
}

func (a *Admin) login(c *gin.Context) {
	if !a.canShowLogin(c) {
		c.Status(http.StatusNotFound)
		return
	}
	c.Header("Referrer-Policy", "no-referrer")
	serveTrustedHTML(c, `<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>管理控制台登录</title>
</head>
<body>
    <main>
        <h1>管理控制台登录</h1>
        <form id="login" method="post" action="/api/v1/media/admin/elevate">
            <label>管理密钥 <input name="token" type="password" autocomplete="current-password" required></label>
            <button type="submit">登录</button>
        </form>
        <p id="message" role="status"></p>
    </main>
    <script>
        const form = document.getElementById('login');
        const button = form.querySelector('button');
        const message = document.getElementById('message');
        form.addEventListener('submit', async (event) => {
            event.preventDefault();
            button.disabled = true;
            message.textContent = '';
            const body = new URLSearchParams(new FormData(form));
            form.reset();
            try {
                const response = await fetch(form.action, {method: 'POST', credentials: 'same-origin', body});
                if (response.ok) {
                    window.location.replace('/api/v1/media/admin/');
                    return;
                }
                message.textContent = '登录失败，请检查管理密钥后重试。';
            } catch {
                message.textContent = '暂时无法登录，请稍后重试。';
            } finally {
                button.disabled = false;
            }
        });
    </script>
</body>
</html>`, false)
}
