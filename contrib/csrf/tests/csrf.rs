#[macro_use] extern crate rocket;

use rocket::error::ErrorKind::SentinelAborts;
use rocket::fs::TempFile;
use rocket::form::FromForm;
use rocket::http::{ContentType, Header, Status};
use rocket::local::blocking::Client;

use rocket_csrf::{
    CSRF_HEADER, Csrf, CsrfForm, CsrfToken, VerifiedXsrf, XSRF_COOKIE, XSRF_HEADER, XsrfToken,
};

#[derive(FromForm)]
struct Login<'r> {
    username: &'r str,
}

#[derive(FromForm)]
struct MultipartLogin<'r> {
    username: &'r str,
}

#[derive(FromForm)]
struct Upload<'r> {
    file: TempFile<'r>,
}

#[get("/token")]
fn token(csrf: CsrfToken) -> String {
    csrf.to_string()
}

#[get("/xsrf")]
fn xsrf(_xsrf: XsrfToken) -> Status {
    Status::NoContent
}

#[post("/submit", data = "<form>")]
fn submit(form: CsrfForm<Login<'_>>) -> String {
    form.username.to_string()
}

#[post("/forward", rank = 1, data = "<form>")]
fn forward_form(form: CsrfForm<Login<'_>>) -> String {
    form.username.to_string()
}

#[post("/forward", rank = 2, data = "<body>")]
fn forward_body(body: String) -> String {
    body
}

#[post("/multipart", data = "<form>")]
fn multipart(form: CsrfForm<MultipartLogin<'_>>) -> String {
    form.username.to_string()
}

#[post("/upload", data = "<form>")]
fn upload(form: CsrfForm<Upload<'_>>) -> &'static str {
    let _ = form;
    "uploaded"
}

#[post("/api")]
fn api(_xsrf: VerifiedXsrf) -> Status {
    Status::Created
}

fn rocket() -> rocket::Rocket<rocket::Build> {
    rocket::build()
        .attach(Csrf::fairing())
        .mount("/", routes![
            token, xsrf, submit, forward_form, forward_body, multipart, upload, api,
        ])
}

#[test]
fn csrf_form_requires_fairing() {
    let rocket = rocket::build().mount("/", routes![token, xsrf, submit, api]);
    let err = Client::debug(rocket).expect_err("sentinel abort");
    assert!(matches!(err.kind(), SentinelAborts(_)));
}

#[test]
fn urlencoded_form_succeeds_with_valid_token() {
    let client = Client::tracked(rocket()).unwrap();
    let token = client.get("/token").dispatch().into_string().unwrap();
    let body = format!("_authenticity_token={token}&username=alice");
    let response = client.post("/submit")
        .header(ContentType::Form)
        .body(body)
        .dispatch();

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string().unwrap(), "alice");
}

#[test]
fn urlencoded_form_rejects_missing_token() {
    let client = Client::tracked(rocket()).unwrap();
    client.get("/token").dispatch();
    let response = client.post("/submit")
        .header(ContentType::Form)
        .body("username=alice")
        .dispatch();

    assert_eq!(response.status(), Status::Forbidden);
}

#[test]
fn urlencoded_form_rejects_invalid_token() {
    let client = Client::tracked(rocket()).unwrap();
    client.get("/token").dispatch();
    let response = client.post("/submit")
        .header(ContentType::Form)
        .body("_authenticity_token=bogus&username=alice")
        .dispatch();

    assert_eq!(response.status(), Status::Forbidden);
}

#[test]
fn csrf_form_forwards_non_form_requests_without_session() {
    let client = Client::tracked(rocket()).unwrap();
    let response = client.post("/forward")
        .header(ContentType::JSON)
        .body("json body")
        .dispatch();

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string().unwrap(), "json body");
}

#[test]
fn multipart_form_succeeds_with_valid_token() {
    let client = Client::tracked(rocket()).unwrap();
    let token = client.get("/token").dispatch().into_string().unwrap();
    let body = [
        "--X-BOUNDARY",
        r#"Content-Disposition: form-data; name="_authenticity_token""#,
        "",
        &token,
        "--X-BOUNDARY",
        r#"Content-Disposition: form-data; name="username""#,
        "",
        "alice",
        "--X-BOUNDARY--",
        "",
    ].join("\r\n");

    let response = client.post("/multipart")
        .header("multipart/form-data; boundary=X-BOUNDARY".parse::<ContentType>().unwrap())
        .body(body)
        .dispatch();

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string().unwrap(), "alice");
}

#[test]
fn multipart_file_upload_requires_token_before_file_fields() {
    let client = Client::tracked(rocket()).unwrap();
    let token = client.get("/token").dispatch().into_string().unwrap();
    let body = [
        "--X-BOUNDARY",
        r#"Content-Disposition: form-data; name="file"; filename="hello.txt""#,
        "Content-Type: text/plain",
        "",
        "hello",
        "--X-BOUNDARY",
        r#"Content-Disposition: form-data; name="_authenticity_token""#,
        "",
        &token,
        "--X-BOUNDARY--",
        "",
    ]
    .join("\r\n");

    let response = client
        .post("/upload")
        .header("multipart/form-data; boundary=X-BOUNDARY".parse::<ContentType>().unwrap())
        .body(body)
        .dispatch();

    assert_eq!(response.status(), Status::Forbidden);
}

#[test]
fn multipart_file_upload_without_content_type_requires_token_before_file_fields() {
    let client = Client::tracked(rocket()).unwrap();
    let token = client.get("/token").dispatch().into_string().unwrap();
    let body = [
        "--X-BOUNDARY",
        r#"Content-Disposition: form-data; name="file"; filename="hello.txt""#,
        "",
        "hello",
        "--X-BOUNDARY",
        r#"Content-Disposition: form-data; name="_authenticity_token""#,
        "",
        &token,
        "--X-BOUNDARY--",
        "",
    ]
    .join("\r\n");

    let response = client
        .post("/upload")
        .header("multipart/form-data; boundary=X-BOUNDARY".parse::<ContentType>().unwrap())
        .body(body)
        .dispatch();

    assert_eq!(response.status(), Status::Forbidden);
}

#[test]
fn multipart_file_upload_succeeds_when_token_precedes_file_fields() {
    let client = Client::tracked(rocket()).unwrap();
    let token = client.get("/token").dispatch().into_string().unwrap();
    let body = [
        "--X-BOUNDARY",
        r#"Content-Disposition: form-data; name="_authenticity_token""#,
        "",
        &token,
        "--X-BOUNDARY",
        r#"Content-Disposition: form-data; name="file"; filename="hello.txt""#,
        "Content-Type: text/plain",
        "",
        "hello",
        "--X-BOUNDARY--",
        "",
    ]
    .join("\r\n");

    let response = client
        .post("/upload")
        .header("multipart/form-data; boundary=X-BOUNDARY".parse::<ContentType>().unwrap())
        .body(body)
        .dispatch();

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string().unwrap(), "uploaded");
}

#[test]
fn multipart_file_upload_without_content_type_succeeds_when_token_precedes_file_fields() {
    let client = Client::tracked(rocket()).unwrap();
    let token = client.get("/token").dispatch().into_string().unwrap();
    let body = [
        "--X-BOUNDARY",
        r#"Content-Disposition: form-data; name="_authenticity_token""#,
        "",
        &token,
        "--X-BOUNDARY",
        r#"Content-Disposition: form-data; name="file"; filename="hello.txt""#,
        "",
        "hello",
        "--X-BOUNDARY--",
        "",
    ]
    .join("\r\n");

    let response = client
        .post("/upload")
        .header("multipart/form-data; boundary=X-BOUNDARY".parse::<ContentType>().unwrap())
        .body(body)
        .dispatch();

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string().unwrap(), "uploaded");
}

#[test]
fn xsrf_guard_sets_framework_cookie() {
    let client = Client::tracked(rocket()).unwrap();
    let response = client.get("/xsrf").dispatch();

    assert_eq!(response.status(), Status::NoContent);
    assert!(response.cookies().get(XSRF_COOKIE).is_some());
}

#[test]
fn header_xsrf_succeeds_with_primary_header() {
    let client = Client::tracked(rocket()).unwrap();
    let response = client.get("/xsrf").dispatch();
    let token = response.cookies().get(XSRF_COOKIE).unwrap().value().to_string();

    let response = client
        .post("/api")
        .header(Header::new(XSRF_HEADER, token))
        .dispatch();
    assert_eq!(response.status(), Status::Created);
}

#[test]
fn header_xsrf_accepts_legacy_header_name() {
    let client = Client::tracked(rocket()).unwrap();
    let response = client.get("/xsrf").dispatch();
    let token = response.cookies().get(XSRF_COOKIE).unwrap().value().to_string();

    let response = client
        .post("/api")
        .header(Header::new(CSRF_HEADER, token))
        .dispatch();
    assert_eq!(response.status(), Status::Created);
}

#[test]
fn header_xsrf_rejects_form_context_token() {
    let client = Client::tracked(rocket()).unwrap();
    let token = client.get("/token").dispatch().into_string().unwrap();

    let response = client
        .post("/api")
        .header(Header::new(XSRF_HEADER, token))
        .dispatch();
    assert_eq!(response.status(), Status::Forbidden);
}

#[test]
fn header_xsrf_rejects_missing_header() {
    let client = Client::tracked(rocket()).unwrap();
    client.get("/xsrf").dispatch();

    let response = client.post("/api").dispatch();
    assert_eq!(response.status(), Status::Forbidden);
}
