/// <reference types="@cloudflare/workers-types" />
import { KVNamespace, R2Bucket } from '@cloudflare/workers-types';
import { Context } from 'hono';

export interface RSSFeed {
    url: string;
    title: string;
    favicon: string;
    addedBy: string;
    addedAt: string;
}

export interface RSSItem {
    title: string;
    author: string;
    date: string;
    link: string;
    content: string;
}

export interface GitHubUser {
    login: string;
    avatar_url: string;
    name?: string;
    email?: string;
}

export interface GitHubTokenResponse {
    access_token: string;
    token_type: string;
    scope: string;
}

export interface Bindings {
    RSS_FEEDS: KVNamespace;
    RSS_BUCKET: R2Bucket;
    GITHUB_CLIENT_ID: string;
    GITHUB_CLIENT_SECRET: string;
    ALLOWED_GITHUB_USERS: string;
    APP_URL: string;
    IMG_PROXY_URL: string;
    [key: string]: unknown;
}

export interface Variables {
    [key: string]: unknown;
}

export type HonoEnv = {
    Bindings: Bindings;
    Variables: Variables;
}

export type AppContext = Context<HonoEnv>;

export type Env = HonoEnv; 
