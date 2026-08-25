/** @type {import('next').NextConfig} */
const API = process.env.DRACARYS_API_URL || "http://127.0.0.1:8000";
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    // Proxy API calls to the FastAPI backend so the browser talks same-origin.
    return [{ source: "/api/:path*", destination: `${API}/api/:path*` }];
  },
};
module.exports = nextConfig;
