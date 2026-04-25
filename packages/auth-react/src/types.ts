import { User, TokenResponse } from '@wilsoon/auth-core';

export interface AuthState {
    user: User | null;
    tokens: TokenResponse | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    error: Error | null;
    login: () => Promise<void>;
    logout: (returnTo?: string) => Promise<void>;
}