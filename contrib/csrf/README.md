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
        r#"<form action=\"/login\" method=\"post\">
            <input type=\"hidden\" name=\"_authenticity_token\" value=\"{csrf}\">
            <button type=\"submit\">Submit</button>
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

See the crate documentation and `examples/csrf` for complete end-to-end usage.
