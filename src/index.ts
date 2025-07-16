import { Hono } from 'hono';
import { githubAuth } from '@hono/oauth-providers/github';
import Parser from 'rss-parser';
import { RSSFeed, RSSItem, Env, Bindings } from './types';

const app = new Hono<{ Bindings: Bindings }>();
const parser = new Parser();

// GitHub OAuth 中间件
const githubMiddleware = async (c: any, next: Function) => {
    try {
        const response = await githubAuth({
            client_id: c.env.GITHUB_CLIENT_ID,
            client_secret: c.env.GITHUB_CLIENT_SECRET,
        })(c, async () => { });

        if (response instanceof Response) {
            return response;
        }

        const allowedUsers = c.env.ALLOWED_GITHUB_USERS.split(',');
        if (!allowedUsers.includes(response.user.login)) {
            return c.text('Unauthorized', 401);
        }

        return next();
    } catch (error) {
        console.error('Auth error:', error);
        return c.text('Authentication failed', 401);
    }
};

// 获取所有RSS订阅源
app.get('/api/feeds', async (c) => {
    const feeds = await c.env?.RSS_FEEDS.get('feeds', 'json') || [];
    return c.json(feeds);
});

// 添加新的RSS订阅源
app.post('/api/feeds', githubMiddleware, async (c) => {
    const { url } = await c.req.json();
    const feeds: RSSFeed[] = await c.env?.RSS_FEEDS.get('feeds', 'json') || [];

    const newFeed: RSSFeed = {
        url,
        addedBy: 'admin', // 这里可以从GitHub OAuth获取用户信息
        addedAt: new Date().toISOString(),
    };

    feeds.push(newFeed);
    await c.env?.RSS_FEEDS.put('feeds', JSON.stringify(feeds));

    return c.json(newFeed);
});

// 获取RSS内容
app.get('/api/rss', async (c) => {
    try {
        // 尝试从R2获取缓存的RSS数据
        const cachedData = await c.env?.RSS_BUCKET.get('rss.json');
        if (cachedData) {
            const data = await cachedData.json();
            return c.json(data);
        }

        // 如果没有缓存，则获取并解析RSS
        const feeds: RSSFeed[] = await c.env?.RSS_FEEDS.get('feeds', 'json') || [];
        const items: RSSItem[] = [];

        for (const feed of feeds) {
            try {
                const feedContent = await parser.parseURL(feed.url);
                for (const item of feedContent.items) {
                    items.push({
                        title: item.title || '',
                        author: item.creator || feedContent.title || '',
                        date: item.pubDate || '',
                        link: item.link || '',
                        content: item.contentSnippet || '',
                    });
                }
            } catch (error) {
                console.error(`Error parsing feed ${feed.url}:`, error);
            }
        }

        // 将解析后的数据存储到R2
        await c.env?.RSS_BUCKET.put('rss.json', JSON.stringify(items));

        return c.json(items);
    } catch (error) {
        console.error('RSS fetch error:', error);
        return c.text('Error fetching RSS feeds', 500);
    }
});

// 删除RSS订阅源
app.delete('/api/feeds/:url', githubMiddleware, async (c) => {
    const url = decodeURIComponent(c.req.param('url'));
    const feeds: RSSFeed[] = await c.env?.RSS_FEEDS.get('feeds', 'json') || [];

    const newFeeds = feeds.filter(feed => feed.url !== url);
    await c.env?.RSS_FEEDS.put('feeds', JSON.stringify(newFeeds));

    return c.json({ success: true });
});

export default app; 