# rocket_csrf

Explicit CSRF protection for Rocket.

`rocket_csrf` provides two explicit, opt-in workflows:

- `CsrfToken` + `CsrfForm<T>` for HTML form submissions
- `XsrfToken` + `VerifiedXsrf` for JavaScript/API requests

Attach `Csrf::fairing()` once, then use the guards that match your routes.

## Form Example

```rust
#[get("/login")]
fn login(csrf: CsrfToken) -> RawHtml<String> {
    RawHtml(format!(
        r#"<form action="/login" method="post">
            <input type="hidden" name="_authenticity_token" value="{csrf}">
            <button type="submit">Submit</button>
        </form>"#,
    ))
}

#[post("/login", data = "<form>")]
fn submit(form: CsrfForm<Login<'_>>) {
    let _login = form.into_inner();
}
```

## XSRF Example

```rust
#[get("/api/bootstrap")]
fn bootstrap(_xsrf: XsrfToken) -> Status {
    Status::NoContent
}

#[post("/api/update")]
fn update(_xsrf: VerifiedXsrf) -> Status {
    Status::Accepted
}
```

In the XSRF flow, the server queues a readable `XSRF-TOKEN` cookie. JavaScript
clients should send that value back in the `X-XSRF-TOKEN` or `X-CSRF-Token`
header on unsafe requests.

## Templates and SPA JSON Responses

Both token guards serialize as strings, so they can be passed directly to a
Rocket template context:

```rust,ignore
#[get("/login")]
fn login(csrf: CsrfToken) -> Template {
    Template::render("login", context! { csrf: csrf })
}
```

Render the token with your template engine's normal autoescaping:

```html
<input type="hidden" name="_authenticity_token" value="{{ csrf }}">
```

For multipart uploads, place this input before file inputs.

An SPA can obtain the header token as JSON instead of reading a cookie:

```rust
#[get("/api/bootstrap")]
fn bootstrap(xsrf: XsrfToken) -> Json<XsrfToken> {
    Json(xsrf)
}
```

The [example's client module](../../examples/csrf/static/csrf-client.js) is
imported by its template and tested directly with Node's built-in test runner.
It single-flights bootstrap calls, surfaces bootstrap/network errors, and retries
at most once only when the response is `403` **and** carries the explicit CSRF
marker. The mutation body is serialized once and replayed unchanged.

A retry-capable route must propagate the guard result before any side effect:

```rust,ignore
#[post("/api/update", data = "<message>")]
fn update(
    xsrf: Result<VerifiedXsrf, CsrfGuardError>,
    message: Json<ApiMessage<'_>>,
) -> Result<String, CsrfGuardError> {
    xsrf?; // return the explicit CSRF error before mutating application state
    // apply_update(message);
    Ok("updated".into())
}
```

`VerifiedXsrf` failures otherwise remain ordinary `403` responses without the
retry marker. This is intentional: Rocket permits `Option`/`Result` guards to
swallow a failure and continue into a handler. Only explicitly returning
`CsrfGuardError::Rejected` emits `X-Rocket-CSRF: csrf-failure`; application
`403`s and swallowed guard failures do not. Never retry mutations based on
status alone.

Enable Rocket's `json` feature to use `Json`. Keep cookies enabled: the token is
bound to a private, HttpOnly session cookie. Token-bearing responses receive
`Cache-Control: no-store`. Session cookies renew after half their configured
lifetime on CSRF-guarded requests. A previous session ID remains valid only until
its original expiry, so renewal never extends old forms indefinitely and browsers
can discard expired cookies. Tokens can be reused until expiration; obtain a new
token after session or token expiration. Only explicit
`CsrfGuardError::Rejected` responses carry `X-Rocket-CSRF: csrf-failure`; default
guard rejections, swallowed guard failures, and application-generated `403`s do
not. Retry a replayable mutation only when both status `403` and this marker are
present. Do not blindly retry every `403`, and surface bootstrap/network errors
to the user. `scripts/test.sh --examples` requires Node.js 20+ and runs the client
module's behavior tests.
The cookie mode remains supported: clients may read the non-HttpOnly
`XSRF-TOKEN` cookie and send it in `X-XSRF-TOKEN` instead of using the JSON body.
The server cannot coordinate concurrent first bootstrap requests that arrive
without a session cookie. The example module's `bootstrapInFlight` promise keeps
its own concurrent calls to one request; separate tabs or clients remain
independent. Subsequent requests must include the cookie.

Protection is opt-in **per route**; the fairing alone does not protect routes.
Form and header tokens are deliberately not interchangeable. Use HTTPS in
production, retain template autoescaping, and do not expose bootstrap endpoints
through permissive CORS. Default host-only, SameSite=Strict cookies support
same-origin SPAs, not truly cross-site frontends.

## Replicas and Restarts

No sticky routing or shared token store is needed. CSRF signing keys are derived
from Rocket's existing `secret_key`, with domain separation from cookie keys.
Configure the **same persistent secret** and identical CSRF settings on every
replica, and preserve them across restarts.

Generate a secret once, store it in your deployment's secret manager, and provide
it to each replica as `ROCKET_SECRET_KEY` (or Rocket.toml's `secret_key`):

```sh
openssl rand -base64 64
```

Do not generate a new secret at each startup or commit it to source control.
Debug-mode auto-generated keys remain intentionally ephemeral; non-debug
profiles already require an explicitly configured secret.

Rotation follows UTC periods anchored to the Unix epoch, not process uptime.
Keep replica clocks synchronized (for example, with NTP). A token from the
previous period is accepted only during `csrf.rotate.window` hours at the start
of the next `csrf.rotate.period`-hour period. Restarting does not reset or extend
token validity. Changing the secret intentionally invalidates both tokens and
private session cookies; changing rotation settings invalidates existing tokens.

See the crate documentation and `examples/csrf` for complete end-to-end usage.
