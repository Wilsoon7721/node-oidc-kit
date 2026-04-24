export interface AuthConfig {
    clientId: string;
    issuer: string;       // Default: https://id.wilsoon.dev
    redirectUri: string;
    scope?: string[];     // Allow overrides, but we'll set defaults
}

export interface TokenResponse {
    access_token: string;
    id_token?: string;
    refresh_token?: string;
    expires_in?: number;
    token_type?: string;
    scope?: string;
}

export interface User {
    id: string;
    email: string;
    role: 'admin' | 'user';
    authMethods: string[];
    sessionVersion: number;
}