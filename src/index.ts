import { Hono } from 'hono';
import { serveStatic } from 'hono/cloudflare-workers';
import { cors } from 'hono/cors';
import Parser from 'rss-parser';
import { RSSFeed, RSSItem, HonoEnv, AppContext, GitHubUser, GitHubTokenResponse } from './types';

const app = new Hono<HonoEnv>();

// 添加CORS中间件，允许所有域名访问
app.use('*', cors({
    origin: ['https://rss-api.040720.xyz', 'https://rss-cloudflare.1946815225.workers.dev', 'http://localhost:4321', 'https://blog.helong.online'],
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'Cookie'],
    exposeHeaders: ['Content-Length', 'Set-Cookie'],
    maxAge: 86400,
    credentials: true,
}));

const parser = new Parser();

// Helper function to sanitize HTML content
function sanitizeContent(content: string): string {
    // Remove HTML tags
    const withoutTags = content.replace(/<[^>]*>/g, '');
    // Decode HTML entities
    const decoded = withoutTags
        .replace(/&quot;/g, '"')
        .replace(/&apos;/g, "'")
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&amp;/g, '&')
        .replace(/&#x([0-9A-Fa-f]+);/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/&#(\d+);/g, (_, dec) => String.fromCharCode(parseInt(dec, 10)));
    // Trim and limit length
    return decoded.trim().slice(0, 100);
}

// 认证中间件
const authMiddleware = async (c: AppContext, next: Function) => {
    try {
        // 检查会话中是否有用户信息
        const userResponse = await fetch('https://api.github.com/user', {
            headers: {
                'Authorization': `Bearer ${c.req.cookie('github_token')}`,
                'User-Agent': 'RSS-Service'
            }
        });

        if (!userResponse.ok) {
            return c.json({ error: 'Unauthorized', message: 'Please login first' }, 401);
        }

        const user: GitHubUser = await userResponse.json();
        const allowedUsers = c.env.ALLOWED_GITHUB_USERS.split(',');

        if (!allowedUsers.includes(user.login)) {
            return c.json({ error: 'Forbidden', message: 'User not allowed' }, 403);
        }

        return next();
    } catch (error) {
        console.error('Auth check failed:', error);
        return c.json({ error: 'Authentication failed', message: 'Please login first' }, 401);
    }
};

// 静态文件服务
app.get('/login', serveStatic({ path: './login.html' }));
app.get('/', authMiddleware, serveStatic({ path: './index.html' }));

// GitHub OAuth 登录端点
app.get('/auth/github', async (c: AppContext) => {
    const params = new URLSearchParams({
        client_id: c.env.GITHUB_CLIENT_ID,
        redirect_uri: `${c.env.APP_URL}/auth/github/callback`,
        scope: 'read:user',
        state: crypto.randomUUID()
    });

    return c.redirect(`https://github.com/login/oauth/authorize?${params.toString()}`);
});

// GitHub OAuth 回调处理
app.get('/auth/github/callback', async (c: AppContext) => {
    try {
        const code = c.req.query('code');

        if (!code) {
            return c.redirect('/login?error=auth_failed&reason=no_code');
        }

        // 获取访问令牌
        const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                client_id: c.env.GITHUB_CLIENT_ID,
                client_secret: c.env.GITHUB_CLIENT_SECRET,
                code
            })
        });

        const tokenData: GitHubTokenResponse = await tokenResponse.json();

        if (!tokenData.access_token) {
            return c.redirect('/login?error=auth_failed&reason=no_token');
        }

        // 获取用户信息
        const userResponse = await fetch('https://api.github.com/user', {
            headers: {
                'Authorization': `Bearer ${tokenData.access_token}`,
                'User-Agent': 'RSS-Service'
            }
        });

        if (!userResponse.ok) {
            return c.redirect('/login?error=auth_failed&reason=user_info_failed');
        }

        const user: GitHubUser = await userResponse.json();
        const allowedUsers = c.env.ALLOWED_GITHUB_USERS.split(',');

        if (!allowedUsers.includes(user.login)) {
            return c.redirect('/login?error=unauthorized');
        }

        // 设置cookie
        c.cookie('github_token', tokenData.access_token, {
            httpOnly: true,
            secure: true,
            sameSite: 'Lax',
            path: '/'
        });

        return c.redirect('/');
    } catch (error) {
        console.error('OAuth callback error:', error);
        return c.redirect('/login?error=auth_failed&reason=callback_error');
    }
});

// 获取所有RSS订阅源
app.get('/api/feeds', authMiddleware, async (c) => {
    try {
        const feeds = await c.env.RSS_FEEDS.get('feeds', 'json') || [];
        return c.json(feeds);
    } catch (error) {
        console.error('Failed to get feeds:', error);
        return c.json([]);
    }
});

// 添加新的RSS订阅源
app.post('/api/feeds', authMiddleware, async (c) => {
    try {
        const { url } = await c.req.json();

        if (!url) {
            return c.json({ error: 'URL is required' }, 400);
        }

        // 验证RSS源并获取标题
        const feedInfo = await validateAndGetFeedInfo(url);
        if (!feedInfo) {
            return c.json({ error: 'Invalid RSS feed URL' }, 400);
        }

        const feeds: RSSFeed[] = await c.env.RSS_FEEDS.get('feeds', 'json') || [];

        // 检查是否已存在
        if (feeds.some(feed => feed.url === url)) {
            return c.json({ error: 'Feed already exists' }, 400);
        }

        const newFeed: RSSFeed = {
            url,
            title: feedInfo.title,
            favicon: `${c.env.IMG_PROXY_URL}?url=${encodeURIComponent(url)}&size=256`,
            addedBy: 'admin',
            addedAt: new Date().toISOString(),
        };

        feeds.push(newFeed);
        await c.env.RSS_FEEDS.put('feeds', JSON.stringify(feeds));

        // 清除R2缓存
        try {
            await c.env.RSS_BUCKET.delete('rss.json');
        } catch (error) {
            console.error('Failed to clear RSS cache:', error);
        }

        return c.json(newFeed);
    } catch (error) {
        console.error('Failed to add feed:', error);
        return c.json({ error: 'Failed to add feed' }, 500);
    }
});

// 验证RSS源并获取信息
async function validateAndGetFeedInfo(url: string) {
    try {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const text = await response.text();
        const feed = await parser.parseString(text);

        if (!feed.items || feed.items.length === 0) {
            return null;
        }

        return {
            title: feed.title || new URL(url).hostname,
            description: feed.description || ''
        };
    } catch (error) {
        console.error(`Failed to validate RSS feed: ${url}`, error);
        return null;
    }
}

// 获取RSS内容的公开API（无需认证）
app.get('/api/rss/public', async (c: AppContext) => {
    try {
        // 尝试从R2获取缓存的RSS数据
        const cachedData = await c.env.RSS_BUCKET.get('rss.json');
        if (cachedData) {
            const data: RSSItem[] = await cachedData.json();
            // 按时间从新到旧排序
            const sortedData = data.sort((a: RSSItem, b: RSSItem) =>
                new Date(b.date).getTime() - new Date(a.date).getTime()
            );
            // 确保返回的数据也遵循100字限制
            const limitedData = sortedData.map((item: RSSItem) => ({
                ...item,
                content: item.content.slice(0, 100)
            }));
            return c.json(limitedData);
        }

        return c.json([], 200);
    } catch (error) {
        console.error('RSS fetch error:', error);
        return c.json({ error: 'Failed to fetch RSS feeds' }, 500);
    }
});

// 原有的需要认证的RSS API
app.get('/api/rss', authMiddleware, async (c: AppContext) => {
    try {
        // 尝试从R2获取缓存的RSS数据
        const cachedData = await c.env.RSS_BUCKET.get('rss.json');
        if (cachedData) {
            const data: RSSItem[] = await cachedData.json();
            // 按时间从新到旧排序
            const sortedData = data.sort((a: RSSItem, b: RSSItem) =>
                new Date(b.date).getTime() - new Date(a.date).getTime()
            );
            // 确保返回的数据也遵循100字限制
            const limitedData = sortedData.map((item: RSSItem) => ({
                ...item,
                content: item.content.slice(0, 100)
            }));
            return c.json(limitedData);
        }

        // 如果没有缓存，则获取并解析RSS
        const feeds: RSSFeed[] = await c.env.RSS_FEEDS.get('feeds', 'json') || [];
        const items: RSSItem[] = [];

        for (const feed of feeds) {
            try {
                const response = await fetch(feed.url);
                if (!response.ok) {
                    console.error(`Failed to fetch feed: ${feed.url}, status: ${response.status}`);
                    continue;
                }

                const text = await response.text();
                const feedContent = await parser.parseString(text);

                for (const item of feedContent.items) {
                    // Try different content fields in order of preference
                    const content = item.summary ||
                        item.description ||
                        item['content:encoded'] ||
                        item.contentSnippet ||
                        item.content ||
                        '';
                    items.push({
                        title: item.title || '',
                        author: item.creator || feedContent.title || '',
                        date: item.pubDate || item.isoDate || '',
                        link: item.link || '',
                        content: sanitizeContent(content),
                    });
                }
            } catch (error) {
                console.error(`Error parsing feed ${feed.url}:`, error);
            }
        }

        // 按时间从新到旧排序
        items.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());

        // 将解析后的数据存储到R2
        if (items.length > 0) {
            await c.env.RSS_BUCKET.put('rss.json', JSON.stringify(items));
        }

        return c.json(items);
    } catch (error) {
        console.error('RSS fetch error:', error);
        return c.json({ error: 'Failed to fetch RSS feeds' }, 500);
    }
});

// 删除RSS订阅源
app.delete('/api/feeds/:url', authMiddleware, async (c) => {
    try {
        const url = decodeURIComponent(c.req.param('url'));
        const feeds: RSSFeed[] = await c.env.RSS_FEEDS.get('feeds', 'json') || [];

        const newFeeds = feeds.filter(feed => feed.url !== url);
        await c.env.RSS_FEEDS.put('feeds', JSON.stringify(newFeeds));

        // 清除R2缓存，以便下次获取新内容
        try {
            await c.env.RSS_BUCKET.delete('rss.json');
        } catch (error) {
            console.error('Failed to clear RSS cache:', error);
        }

        return c.json({ success: true });
    } catch (error) {
        console.error('Failed to delete feed:', error);
        return c.json({ error: 'Failed to delete feed' }, 500);
    }
});

// 获取用户信息
app.get('/api/user', async (c) => {
    try {
        const userResponse = await fetch('https://api.github.com/user', {
            headers: {
                'Authorization': `Bearer ${c.req.cookie('github_token')}`,
                'User-Agent': 'RSS-Service'
            }
        });

        if (!userResponse.ok) {
            return c.json({ error: 'Failed to get user info' }, 401);
        }

        const user: GitHubUser = await userResponse.json();
        return c.json(user);
    } catch (error) {
        console.error('Failed to get user info:', error);
        return c.json({ error: 'Failed to get user info' }, 500);
    }
});

// 刷新RSS内容
app.post('/api/rss/refresh', async (c) => {
    try {
        const feeds: RSSFeed[] = await c.env.RSS_FEEDS.get('feeds', 'json') || [];
        const items: RSSItem[] = [];

        for (const feed of feeds) {
            try {
                const response = await fetch(feed.url);
                if (!response.ok) {
                    console.error(`Failed to fetch feed: ${feed.url}, status: ${response.status}`);
                    continue;
                }

                const text = await response.text();
                const feedContent = await parser.parseString(text);

                for (const item of feedContent.items) {
                    // Try different content fields in order of preference
                    const content = (item.summary ||
                        item.description ||
                        item['content:encoded'] ||
                        item.contentSnippet ||
                        item.content ||
                        '').trim();
                    items.push({
                        title: item.title || '',
                        author: item.creator || feedContent.title || '',
                        date: item.pubDate || item.isoDate || '',
                        link: item.link || '',
                        content: sanitizeContent(content),
                    });
                }
            } catch (error) {
                console.error(`Error parsing feed ${feed.url}:`, error);
            }
        }

        // 按时间从新到旧排序
        items.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());

        // 更新R2缓存
        if (items.length > 0) {
            await c.env.RSS_BUCKET.put('rss.json', JSON.stringify(items));
        }

        return c.json({ success: true });
    } catch (error) {
        console.error('Failed to refresh RSS:', error);
        return c.json({ error: 'Failed to refresh RSS' }, 500);
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

export default app; 
