import { Hono } from 'hono';
import { cors } from 'hono/cors';
import Parser from 'rss-parser';
import { RSSFeed, RSSItem, HonoEnv, AppContext, GitHubUser, GitHubTokenResponse, Bindings } from './types';

const app = new Hono<HonoEnv>();

// 添加CORS中间件
app.use('*', cors({
    origin: ['https://rss-api.040720.xyz', 'https://rss-cloudflare.1946815225.workers.dev', 'http://localhost:4321', 'https://blog.helong.online'],
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'Cookie'],
    exposeHeaders: ['Content-Length', 'Set-Cookie'],
    maxAge: 86400,
    credentials: true,
}));

const parser = new Parser();

// 内容清理函数
function sanitizeContent(content: string): string {
    return content
        .replace(/<[^>]*>/g, '')
        .replace(/&[^;]+;/g, ' ')
        .trim()
        .slice(0, 100);
}

// 认证中间件
const authMiddleware = async (c: AppContext, next: () => Promise<void>) => {
    try {
        const token = c.req.cookie('github_token');
        if (!token) {
            return c.json({ error: 'Authentication required', message: 'Please login first' }, 401);
        }

        const userResponse = await fetch('https://api.github.com/user', {
            headers: {
                'Authorization': `Bearer ${token}`,
                'User-Agent': 'RSS-Service'
            }
        });

        if (!userResponse.ok) {
            return c.json({ error: 'Invalid token', message: 'Please login again' }, 401);
        }

        const user: GitHubUser = await userResponse.json();
        const allowedUsers = c.env.ALLOWED_GITHUB_USERS.split(',');

        if (!allowedUsers.includes(user.login)) {
            return c.json({ error: 'Access denied', message: 'User not authorized' }, 403);
        }

        return next();
    } catch (error) {
        console.error('Auth check failed:', error);
        return c.json({ error: 'Authentication failed', message: 'Please login first' }, 401);
    }
};

// 静态文件路由 - 移除 serveStatic
app.get('/login', (c) => {
    return c.html(`<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录 - RSS订阅服务</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 400px; margin: 100px auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .login-btn { background: #24292e; color: white; padding: 12px 24px; border: none; border-radius: 6px; text-decoration: none; display: inline-block; margin-top: 20px; }
        .login-btn:hover { background: #444; }
    </style>
</head>
<body>
    <div class="container">
        <h1>RSS订阅服务</h1>
        <p>请使用GitHub账号登录</p>
        <a href="/auth/github" class="login-btn">使用GitHub登录</a>
    </div>
</body>
</html>`);
});

app.get('/', authMiddleware, (c) => {
    return c.html(`<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RSS订阅服务</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        button { padding: 10px 20px; margin: 5px; border: none; border-radius: 5px; cursor: pointer; }
        .success { background: #28a745; color: white; }
        .warning { background: #f59e0b; color: white; }
        .info { background: #17a2b8; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>RSS订阅服务</h1>
            <div>
                <button class="success" onclick="refreshRSS()">刷新</button>
                <button class="warning" onclick="testCronJob()">测试定时抓取</button>
                <button onclick="handleLogout()">退出登录</button>
            </div>
        </div>
        <div id="content">
            <p>RSS订阅服务正在运行...</p>
        </div>
    </div>
    <script>
        async function refreshRSS() {
            alert('刷新功能');
        }
        async function testCronJob() {
            alert('测试定时抓取功能');
        }
        function handleLogout() {
            window.location.href = '/login';
        }
    </script>
</body>
</html>`);
});
