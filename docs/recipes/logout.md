---
title: Logout
identifier: logout
order: 6
---

Send the user to the provider's `end_session_endpoint` so it can end its own session, and clear
yours.

```ts
const url = await client.getLogoutUrl(tokens.id_token, "https://app.example.com/goodbye");
client.clearStorage(); // your session and transient cookies
return redirect(url);
```

Without an ID token, `getLogoutUrl()` sends `client_id` instead (RP-Initiated Logout 1.0). The
provider then knows which application asked, but not which session, and may ask the user to
confirm.

In React, `logout()` does all of this:

```tsx
<button onClick={() => logout("https://app.example.com/goodbye")}>Sign out</button>
```

Two things to know:

- The `post_logout_redirect_uri` must be registered with the provider, or it will refuse to
  send the user back there. WilsoonID accepts any URI sharing an origin with one of your
  registered redirect URIs.
- Clear your app's cookies yourself. The provider can only clear the cookies it set.
