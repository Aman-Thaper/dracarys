import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "DRACARYS — Autonomous Red Team",
  description: "ATTACK. PROVE. FIX. RETEST.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen font-sans antialiased">{children}</body>
    </html>
  );
}
