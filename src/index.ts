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
const DEFAULT_FETCH_INTERVAL = 30; // 30分钟间隔

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

// GitHub OAuth 路由
app.get('/auth/github', (c) => {
    const clientId = c.env.GITHUB_CLIENT_ID;
    const redirectUri = `${c.env.APP_URL}/auth/github/callback`;
    const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=user:email`;
    return c.redirect(githubAuthUrl);
});

app.get('/auth/github/callback', async (c) => {
    const code = c.req.query('code');
    if (!code) {
        return c.redirect('/login?error=auth_failed&reason=no_code');
    }

    try {
        const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                client_id: c.env.GITHUB_CLIENT_ID,
                client_secret: c.env.GITHUB_CLIENT_SECRET,
                code: code,
            }),
        });

        const tokenData: GitHubTokenResponse = await tokenResponse.json();
        
        if (!tokenData.access_token) {
            return c.redirect('/login?error=auth_failed&reason=no_token');
        }

        const userResponse = await fetch('https://api.github.com/user', {
            headers: {
                'Authorization': `Bearer ${tokenData.access_token}`,
                'User-Agent': 'RSS-Service'
            }
        });

        const user: GitHubUser = await userResponse.json();
        const allowedUsers = c.env.ALLOWED_GITHUB_USERS.split(',');

        if (!allowedUsers.includes(user.login)) {
            return c.redirect('/login?error=unauthorized');
        }

        const response = c.redirect('/');
        response.headers.set('Set-Cookie', `github_token=${tokenData.access_token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400`);
        return response;
    } catch (error) {
        console.error('OAuth callback error:', error);
        return c.redirect('/login?error=auth_failed&reason=server_error');
    }
});

// 获取用户信息
app.get('/api/user', async (c) => {
    try {
        const token = c.req.cookie('github_token');
        if (!token) {
            return c.json({ error: 'Not authenticated' }, 401);
        }

        const userResponse = await fetch('https://api.github.com/user', {
            headers: {
                'Authorization': `Bearer ${token}`,
                'User-Agent': 'RSS-Service'
            }
        });

        if (!userResponse.ok) {
            return c.json({ error: 'Invalid token' }, 401);
        }

        const user: GitHubUser = await userResponse.json();
        return c.json(user);
    } catch (error) {
        return c.json({ error: 'Failed to get user info' }, 500);
    }
});

// 获取订阅源列表
app.get('/api/feeds', authMiddleware, async (c) => {
    try {
        const feeds: RSSFeed[] = await c.env.RSS_FEEDS.get('feeds', 'json') || [];
        return c.json(feeds);
    } catch (error) {
        return c.json({ error: 'Failed to load feeds' }, 500);
    }
});

// 添加订阅源
app.post('/api/feeds', authMiddleware, async (c) => {
    try {
        const { url } = await c.req.json();
        if (!url) {
            return c.json({ error: 'URL is required' }, 400);
        }

        const feeds: RSSFeed[] = await c.env.RSS_FEEDS.get('feeds', 'json') || [];
        
        if (feeds.some(feed => feed.url === url)) {
            return c.json({ error: 'Feed already exists' }, 400);
        }

        const response = await fetch(url);
        if (!response.ok) {
            return c.json({ error: 'Invalid RSS URL' }, 400);
        }

        const text = await response.text();
        const feedContent = await parser.parseString(text);
        
        const newFeed: RSSFeed = {
            url,
            title: feedContent.title || 'Unknown Feed',
            favicon: `${c.env.IMG_PROXY_URL}/${new URL(url).hostname}`,
            addedBy: 'user',
            addedAt: new Date().toISOString()
        };

        feeds.push(newFeed);
        await c.env.RSS_FEEDS.put('feeds', JSON.stringify(feeds));
        
        return c.json({ success: true });
    } catch (error) {
        return c.json({ error: 'Failed to add feed' }, 500);
    }
});

// 删除订阅源
app.delete('/api/feeds/:url', authMiddleware, async (c) => {
    try {
        const encodedUrl = c.req.param('url');
        const url = decodeURIComponent(encodedUrl);
        
        const feeds: RSSFeed[] = await c.env.RSS_FEEDS.get('feeds', 'json') || [];
        const filteredFeeds = feeds.filter(feed => feed.url !== url);
        
        if (filteredFeeds.length === feeds.length) {
            return c.json({ error: 'Feed not found' }, 404);
        }

        await c.env.RSS_FEEDS.put('feeds', JSON.stringify(filteredFeeds));
        return c.json({ success: true });
    } catch (error) {
        return c.json({ error: 'Failed to delete feed' }, 500);
    }
});

// 获取RSS内容（公开API）
app.get('/api/rss/public', async (c) => {
    try {
        const rssData = await c.env.RSS_BUCKET.get('rss.json');
        if (!rssData) {
            return c.json([]);
        }
        
        const items: RSSItem[] = JSON.parse(await rssData.text());
        const author = c.req.query('author');
        
        if (author) {
            const filteredItems = items.filter(item => 
                item.author.toLowerCase().includes(author.toLowerCase())
            );
            return c.json(filteredItems);
        }
        
        return c.json(items);
    } catch (error) {
        console.error('Failed to load RSS content:', error);
        return c.json({ error: 'Failed to load RSS content' }, 500);
    }
});

// 刷新RSS内容
app.post('/api/rss/refresh', authMiddleware, async (c) => {
    try {
        await refreshAllFeeds(c.env);
        return c.json({ success: true, message: 'RSS content refreshed' });
    } catch (error) {
        return c.json({ error: 'Failed to refresh RSS content' }, 500);
    }
});

// 导出：
export default {
  fetch: app.fetch,
  scheduled: async (event: ScheduledEvent, env: HonoEnv['Bindings'], ctx: ExecutionContext) => {
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
};
