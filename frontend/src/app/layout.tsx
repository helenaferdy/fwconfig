import type { Metadata } from "next";
import localFont from "next/font/local";
import "./globals.css";

/* Robotic mono: use Geist Mono as the single UI typeface */
const robot = localFont({
  src: "./fonts/GeistMonoVF.woff",
  variable: "--font-robot",
  weight: "100 900",
});

export const metadata: Metadata = {
  title: "FWM // Configuration Analysis",
  description:
    "Deterministic firewall configuration analysis and human-readable documentation",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${robot.variable} font-mono antialiased bg-[var(--bg)] text-[var(--fg)]`}
      >
        {children}
      </body>
    </html>
  );
}
