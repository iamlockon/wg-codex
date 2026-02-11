export type EntryApiErrorCode =
  | "missing_bearer_token"
  | "invalid_access_token"
  | "revoked_access_token"
  | "subscription_inactive"
  | "region_not_allowed_by_plan"
  | "unknown_device"
  | "active_session_exists"
  | string;

export interface EntryApiError {
  error: EntryApiErrorCode;
}

export interface WireGuardClientConfig {
  endpoint: string;
  server_public_key: string;
  preshared_key: string | null;
  assigned_ip: string;
  dns_servers: string[];
  persistent_keepalive_secs: number;
  qr_payload: string;
}

export interface Device {
  id: string;
  customer_id: string;
  name: string;
  public_key: string;
  created_at: string;
}

export interface StartSessionRequest {
  device_id: string;
  region: string;
  country_code?: string;
  city_code?: string;
  pool?: string;
  reconnect_session_key?: string;
  node_hint?: string;
}

export interface StartSessionActiveResponse {
  status: "active";
  session_key: string;
  region: string;
  config: WireGuardClientConfig;
}

export interface StartSessionConflictResponse {
  status: "conflict";
  existing_session_key: string;
  message: "active_session_exists";
}

export type StartSessionResponse =
  | StartSessionActiveResponse
  | StartSessionConflictResponse;

export interface CurrentSessionResponse {
  active: boolean;
  session_key: string | null;
  region: string | null;
  device_id: string | null;
  connected_at: string | null;
}

export interface OAuthCallbackRequest {
  code: string;
  code_verifier?: string;
  nonce?: string;
}

export interface OAuthCallbackResponse {
  provider: string;
  customer_id: string;
  access_token: string;
}
