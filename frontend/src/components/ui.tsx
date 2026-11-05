import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from "react";
import { LoaderCircle, TriangleAlert } from "lucide-react";
export function Button({
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement>) {
  return <button className={`button ${className}`} {...props} />;
}
export function Card({
  className = "",
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return <div className={`card ${className}`} {...props} />;
}
export function StatusIndicator({
  tone,
  children,
}: {
  tone: "ok" | "warning" | "neutral";
  children: ReactNode;
}) {
  return (
    <span className={`status ${tone}`}>
      <span className="status-dot" aria-hidden="true" />
      {children}
    </span>
  );
}
export function LoadingState({
  children = "Connecting to API…",
}: {
  children?: ReactNode;
}) {
  return (
    <span className="state" role="status">
      <LoaderCircle size={14} className="spin" aria-hidden="true" />
      {children}
    </span>
  );
}
export function ErrorState({ children }: { children: ReactNode }) {
  return (
    <span className="state error" role="status">
      <TriangleAlert size={14} aria-hidden="true" />
      {children}
    </span>
  );
}
