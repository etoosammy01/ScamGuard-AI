export type User = {
  id: string;
  full_name: string;
  email: string;
  bio: string;
  role: "user" | "admin";
  created_at: string;
};
export type Registration = {
  full_name: string;
  email: string;
  password: string;
  confirm_password: string;
};
export type AuthState =
  | { status: "loading"; user: null }
  | { status: "authenticated"; user: User }
  | { status: "unauthenticated"; user: null }
  | { status: "error"; user: null };
