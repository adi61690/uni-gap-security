import type { NextConfig } from 'next';
const isGitHubPages = process.env.GITHUB_PAGES === 'true';
const basePath = isGitHubPages ? '/uni-gap-security' : '';
const nextConfig: NextConfig = {
	reactStrictMode: true,
	output: 'export',
	basePath,
	trailingSlash: true,
	images: { unoptimized: true },
	env: { NEXT_PUBLIC_BASE_PATH: basePath },
	...(isGitHubPages ? { assetPrefix: '/uni-gap-security/' } : {}),
};
export default nextConfig;
