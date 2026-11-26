import "./globals.css";

export const metadata = {
  title: "AgentGuard | Control Plane",
  description: "AI agent and non-human identity security control plane."
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
