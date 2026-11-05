export type Health = {
  status: "ok";
  service: "scamguard-api";
  version: string;
};
export type ConnectionState = "loading" | "connected" | "unavailable";
