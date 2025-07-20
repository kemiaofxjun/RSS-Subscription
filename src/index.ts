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

// 手动触发定时抓取（用于测试）
app.post('/api/cron/test', authMiddleware, async (c) => {
    try {
        console.log('Manual cron test triggered');
        await refreshAllFeeds(c.env);
        await c.env.RSS_FEEDS.put(LAST_FETCH_TIME_KEY, Date.now().toString());
        return c.json({ success: true, message: '定时抓取测试执行成功' });
    } catch (error) {
        console.error('Manual cron test failed:', error);
        return c.json({ error: '定时抓取测试执行失败' }, 500);
    }
});

// ====== 定时抓取相关 ======
const LAST_FETCH_TIME_KEY = 'rss_last_fetch_time';
const DEFAULT_FETCH_INTERVAL = 30; // 固定30分钟间隔

// 定时任务入口（Cloudflare Worker Cron）
export async function scheduled(event: ScheduledEvent, env: HonoEnv['Bindings'], ctx: ExecutionContext) {
    const lastFetchStr = await env.RSS_FEEDS.get(LAST_FETCH_TIME_KEY);
    const lastFetch = parseInt(lastFetchStr || '0', 10);
    const now = Date.now();
    
    console.log(`Cron triggered. Last fetch: ${lastFetch}, Now: ${now}`);
    
    if (now - lastFetch >= DEFAULT_FETCH_INTERVAL * 60 * 1000) {
        console.log('Executing RSS refresh...');
        await refreshAllFeeds(env);
        await env.RSS_FEEDS.put(LAST_FETCH_TIME_KEY, now.toString());
        console.log('RSS refresh completed');
    } else {
        console.log('Skipping refresh - not enough time passed');
    }
}

// 定时抓取所有订阅源并存储到R2
async function refreshAllFeeds(env: HonoEnv['Bindings']) {
    const feeds: RSSFeed[] = await env.RSS_FEEDS.get('feeds', 'json') || [];
    const items: RSSItem[] = [];
    
    console.log(`Refreshing ${feeds.length} feeds`);
    
    for (const feed of feeds) {
        try {
            const response = await fetch(feed.url);
            if (!response.ok) {
                console.error(`Failed to fetch ${feed.url}: ${response.status}`);
                continue;
            }
            const text = await response.text();
            const feedContent = await parser.parseString(text);
            for (const item of feedContent.items) {
                const content = (item.summary || item.description || item['content:encoded'] || item.contentSnippet || item.content || '').trim();
                items.push({
                    title: item.title || '',
                    author: item.creator || feedContent.title || '',
                    date: item.pubDate || item.isoDate || '',
                    link: item.link || '',
                    content: sanitizeContent(content),
                });
            }
        } catch (e) { 
            console.error(`Error parsing feed ${feed.url}:`, e);
        }
    }
    
    items.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
    if (items.length > 0) {
        await env.RSS_BUCKET.put('rss.json', JSON.stringify(items));
        console.log(`Stored ${items.length} RSS items to R2`);
    }
}

// ES Module 默认导出
export default app;
