"use client";
import { useEffect, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { authDestination } from "@/lib/auth-validation";
import { useAuth } from "./auth-provider";
import { Button, Card, ErrorState, LoadingState } from "./ui";
export function AuthGuard({
  children,
  guestOnly = false,
}: {
  children: ReactNode;
  guestOnly?: boolean;
}) {
  const { state, refresh } = useAuth();
  const router = useRouter();
  const destination = authDestination(state.status, guestOnly);
  useEffect(() => {
    if (destination) router.replace(destination);
  }, [destination, router]);
  if (state.status === "loading" || destination) return <SessionLoading />;
  if (state.status === "error")
    return (
      <div className="container auth-state">
        <Card>
          <ErrorState>
            Unable to check your session. Your connection may be unavailable.
          </ErrorState>
          <Button onClick={() => void refresh()}>Try again</Button>
        </Card>
      </div>
    );
  return children;
}
export function SessionLoading() {
  return (
    <div className="container auth-state">
      <Card>
        <LoadingState>Checking your secure session…</LoadingState>
      </Card>
    </div>
  );
}
