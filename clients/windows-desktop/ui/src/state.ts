export type AppSessionState =
  | { kind: "unauthenticated" }
  | { kind: "authenticated_idle"; customerId: string }
  | { kind: "connecting"; customerId: string; region: string }
  | { kind: "connected"; customerId: string; sessionKey: string; region: string }
  | { kind: "disconnecting"; customerId: string; sessionKey: string }
  | { kind: "error_recoverable"; customerId?: string; message: string };

export const initialAppSessionState: AppSessionState = {
  kind: "unauthenticated",
};
