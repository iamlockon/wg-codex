import type {
  CurrentSessionResponse,
  Device,
  EntryApiError,
  OAuthCallbackRequest,
  OAuthCallbackResponse,
  StartSessionRequest,
  StartSessionResponse,
} from "./contracts";

export class EntryApiClient {
  constructor(
    private readonly baseUrl: string,
    private readonly getAccessToken: () => string | null,
  ) {}

  async oauthCallback(
    provider: string,
    payload: OAuthCallbackRequest,
  ): Promise<OAuthCallbackResponse> {
    return this.request(`/v1/auth/oauth/${provider}/callback`, {
      method: "POST",
      body: JSON.stringify(payload),
      headers: { "content-type": "application/json" },
      auth: false,
    });
  }

  async logout(): Promise<void> {
    await this.request(`/v1/auth/logout`, {
      method: "POST",
      auth: true,
    });
  }

  async listDevices(): Promise<Device[]> {
    return this.request(`/v1/devices`, { method: "GET", auth: true });
  }

  async registerDevice(name: string, publicKey: string): Promise<Device> {
    return this.request(`/v1/devices`, {
      method: "POST",
      auth: true,
      body: JSON.stringify({ name, public_key: publicKey }),
      headers: { "content-type": "application/json" },
    });
  }

  async startSession(payload: StartSessionRequest): Promise<StartSessionResponse> {
    return this.request(`/v1/sessions/start`, {
      method: "POST",
      auth: true,
      body: JSON.stringify(payload),
      headers: { "content-type": "application/json" },
    });
  }

  async terminateSession(sessionKey: string): Promise<void> {
    await this.request(`/v1/sessions/${sessionKey}/terminate`, {
      method: "POST",
      auth: true,
    });
  }

  async currentSession(): Promise<CurrentSessionResponse> {
    return this.request(`/v1/sessions/current`, { method: "GET", auth: true });
  }

  private async request<T>(
    path: string,
    options: {
      method: "GET" | "POST";
      headers?: Record<string, string>;
      body?: string;
      auth: boolean;
    },
  ): Promise<T> {
    const headers = new Headers(options.headers ?? {});
    if (options.auth) {
      const token = this.getAccessToken();
      if (!token) {
        throw new Error("missing_access_token");
      }
      headers.set("authorization", `Bearer ${token}`);
    }

    const response = await fetch(`${this.baseUrl}${path}`, {
      method: options.method,
      headers,
      body: options.body,
    });

    if (!response.ok) {
      const maybeErr = (await this.tryJson(response)) as EntryApiError | null;
      throw new EntryApiRequestError(
        response.status,
        maybeErr?.error ?? "unknown_error",
      );
    }

    if (response.status === 204) {
      return undefined as T;
    }
    return (await response.json()) as T;
  }

  private async tryJson(response: Response): Promise<unknown | null> {
    const text = await response.text();
    if (!text) {
      return null;
    }
    try {
      return JSON.parse(text);
    } catch {
      return null;
    }
  }
}

export class EntryApiRequestError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
  ) {
    super(`entry_api_error:${status}:${code}`);
  }
}
