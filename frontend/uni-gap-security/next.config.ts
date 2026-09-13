import type { NextConfig } from 'next';
const isGitHubPages = process.env.GITHUB_PAGES === 'true';
const nextConfig: NextConfig = {
	reactStrictMode: true,
	...(isGitHubPages ? { output: 'export' as const, basePath: '/uni-gap-security', assetPrefix: '/uni-gap-security/', images: { unoptimized: true } } : {}),
};
export default nextConfig;
