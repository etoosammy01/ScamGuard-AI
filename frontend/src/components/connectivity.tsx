"use client";
import { useEffect, useState } from "react";
import { getHealth } from "@/lib/api";
import type { ConnectionState } from "@/types/api";
import { ErrorState, LoadingState, StatusIndicator } from "./ui";
export function Connectivity() {
  const [state, setState] = useState<ConnectionState>("loading");
  useEffect(() => {
    const controller = new AbortController();
    async function check() {
      try {
        await getHealth(controller.signal);
        if (!controller.signal.aborted) setState("connected");
      } catch {
        if (!controller.signal.aborted) setState("unavailable");
      }
    }
    void check();
    const timer = setInterval(() => void check(), 30000);
    return () => {
      controller.abort();
      clearInterval(timer);
    };
  }, []);
  return (
    <div aria-live="polite">
      {state === "loading" ? (
        <LoadingState />
      ) : state === "connected" ? (
        <StatusIndicator tone="ok">API connected</StatusIndicator>
      ) : (
        <ErrorState>API unavailable · retrying automatically</ErrorState>
      )}
    </div>
  );
}
