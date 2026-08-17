/**
 * Static export, deliberately.
 *
 * The Worker already carries the SSH crypto and the whole API surface. Putting
 * Next's server runtime inside it via an SSR adapter would compete for script
 * size and force /ws and /api/* to be routed around the adapter's handler. This
 * app needs no server rendering at all, so `next build` emits plain files into
 * out/ and Workers static assets serve them.
 *
 * Consequences to remember: no API routes, no middleware, no image
 * optimization. All server logic lives in the Worker and the Durable Object.
 *
 * @type {import('next').NextConfig}
 */
const nextConfig = {
  output: 'export',
  trailingSlash: false,
  images: { unoptimized: true },
  reactStrictMode: true,
};

export default nextConfig;
