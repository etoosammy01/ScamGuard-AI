"use client";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  APIError,
  currentUser,
  signIn,
  signOut,
  UNAUTHORIZED_EVENT,
} from "@/lib/auth-api";
import type { AuthState, User } from "@/types/auth";
type AuthContextValue = {
  state: AuthState;
  refresh: () => Promise<void>;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  setUser: (user: User) => void;
};
const AuthContext = createContext<AuthContextValue | null>(null);
export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    status: "loading",
    user: null,
  });
  const epoch = useRef(0);
  const active = useRef<AbortController | null>(null);
  const cancelPending = useCallback(() => {
    ++epoch.current;
    active.current?.abort();
  }, []);
  const refresh = useCallback(async () => {
    const version = ++epoch.current;
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    try {
      const user = await currentUser(controller.signal);
      if (epoch.current === version)
        setState({ status: "authenticated", user });
    } catch (error) {
      if (epoch.current === version && !controller.signal.aborted)
        setState({
          status:
            error instanceof APIError && error.status === 401
              ? "unauthenticated"
              : "error",
          user: null,
        });
    }
  }, []);
  const setUser = useCallback((user: User) => {
    ++epoch.current;
    active.current?.abort();
    setState({ status: "authenticated", user });
  }, []);
  const login = useCallback(
    async (email: string, password: string) => {
      ++epoch.current;
      active.current?.abort();
      const user = await signIn(email, password);
      setUser(user);
    },
    [setUser],
  );
  const logout = useCallback(async () => {
    ++epoch.current;
    active.current?.abort();
    await signOut();
    ++epoch.current;
    setState({ status: "unauthenticated", user: null });
    // Inform other tabs without persisting authentication data.
    const channel =
      typeof BroadcastChannel !== "undefined"
        ? new BroadcastChannel("scamguard-auth")
        : null;
    channel?.postMessage("logout");
    channel?.close();
  }, []);
  useEffect(() => {
    const initial = setTimeout(() => void refresh(), 0);
    const invalidate = () => {
      ++epoch.current;
      active.current?.abort();
      setState({ status: "unauthenticated", user: null });
    };
    const onFocus = () => {
      void refresh();
    };
    window.addEventListener(UNAUTHORIZED_EVENT, invalidate);
    window.addEventListener("focus", onFocus);
    const timer = setInterval(onFocus, 60000);
    const channel =
      typeof BroadcastChannel !== "undefined"
        ? new BroadcastChannel("scamguard-auth")
        : null;
    if (channel)
      channel.onmessage = (event) => {
        if (event.data === "logout") invalidate();
      };
    return () => {
      cancelPending();
      clearTimeout(initial);
      clearInterval(timer);
      channel?.close();
      window.removeEventListener(UNAUTHORIZED_EVENT, invalidate);
      window.removeEventListener("focus", onFocus);
    };
  }, [refresh, cancelPending]);
  return (
    <AuthContext.Provider value={{ state, refresh, login, logout, setUser }}>
      {children}
    </AuthContext.Provider>
  );
}
export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("AuthProvider is required");
  return value;
}
