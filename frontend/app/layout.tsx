import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Recon_FW - Security Reconnaissance Dashboard",
  description: "Dashboard for security reconnaissance framework",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body>{children}</body>
    </html>
  );
}

