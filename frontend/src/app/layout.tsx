import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = {
  title: "ScamGuard AI — Stay one step ahead",
  description:
    "A security platform in development to help you understand suspicious messages, phishing links, and scam indicators.",
};
export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <a className="skip-link" href="#main">
          Skip to content
        </a>
        {children}
      </body>
    </html>
  );
}
