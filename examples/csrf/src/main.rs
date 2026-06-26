#[macro_use]
extern crate rocket;

#[cfg(test)]
mod tests;

use rocket::form::FromForm;
use rocket::response::content::RawHtml;
use rocket::serde::{Deserialize, Serialize, json::Json};
use rocket::http::Status;

use rocket_csrf::{
    Csrf, CsrfForm, CsrfToken, VerifiedXsrf, XSRF_COOKIE, XSRF_HEADER, XsrfToken,
};

#[derive(FromForm)]
struct Message<'r> {
    message: &'r str,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
struct ApiMessage<'r> {
    message: &'r str,
}

#[get("/")]
fn index(csrf: CsrfToken) -> RawHtml<String> {
    RawHtml(format!(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Rocket CSRF Example</title>
  </head>
  <body>
    <h1>Explicit CSRF Example</h1>
    <p>This form uses <code>CsrfToken</code> and <code>CsrfForm&lt;T&gt;</code>.</p>
    <form action="/" method="post">
      <input type="hidden" name="_authenticity_token" value="{csrf}">
      <label>
        Message
        <input type="text" name="message" value="Hello, Rocket!">
      </label>
      <button type="submit">Send</button>
    </form>
    <hr>
    <h2>JavaScript API Example</h2>
    <p>
      The script below requests a readable <code>{XSRF_COOKIE}</code> cookie,
      then sends it back in the <code>{XSRF_HEADER}</code> header.
    </p>
    <button id="api-send" type="button">Send API Request</button>
    <pre id="api-result">waiting...</pre>
    <script>
      const xsrfCookie = "{XSRF_COOKIE}";
      const xsrfHeader = "{XSRF_HEADER}";

      function cookie(name) {{
        const prefix = `${{name}}=`;
        for (const part of document.cookie.split(/;\s*/)) {{
          if (part.startsWith(prefix)) {{
            return decodeURIComponent(part.slice(prefix.length));
          }}
        }}

        return null;
      }}

      document.getElementById("api-send").addEventListener("click", async () => {{
        await fetch("/api/bootstrap", {{ credentials: "same-origin" }});
        const token = cookie(xsrfCookie);
        const response = await fetch("/api/message", {{
          method: "POST",
          credentials: "same-origin",
          headers: {{
            "Content-Type": "application/json",
            [xsrfHeader]: token,
          }},
          body: JSON.stringify({{ message: "Hello from fetch()" }}),
        }});

        document.getElementById("api-result").textContent = await response.text();
      }});
    </script>
  </body>
</html>"#
    ))
}

#[post("/", data = "<form>")]
fn submit(form: CsrfForm<Message<'_>>) -> RawHtml<String> {
    RawHtml(format!("<p>Accepted message: {}</p>", form.message))
}

#[get("/api/bootstrap")]
fn bootstrap(_xsrf: XsrfToken) -> Status {
    Status::NoContent
}

#[post("/api/message", format = "json", data = "<message>")]
fn api_message(_xsrf: VerifiedXsrf, message: Json<ApiMessage<'_>>) -> String {
    format!("accepted api message: {}", message.message)
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(Csrf::fairing())
        .mount("/", routes![index, submit, bootstrap, api_message])
}
