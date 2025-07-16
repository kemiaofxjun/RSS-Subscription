/// <reference types="@cloudflare/workers-types" />
import { KVNamespace, R2Bucket } from '@cloudflare/workers-types';

export interface RSSFeed {
    url: string;
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

export interface Bindings {
    [key: string]: unknown;
    RSS_FEEDS: KVNamespace;
    RSS_BUCKET: R2Bucket;
    GITHUB_CLIENT_ID: string;
    GITHUB_CLIENT_SECRET: string;
    ALLOWED_GITHUB_USERS: string;
}

export type Env = {
    Bindings: Bindings;
} 