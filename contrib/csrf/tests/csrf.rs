#[macro_use] extern crate rocket;

use std::sync::atomic::{AtomicUsize, Ordering};

use rocket::error::ErrorKind::SentinelAborts;
use rocket::fs::TempFile;
use rocket::form::FromForm;
use rocket::http::{ContentType, Header, Status};
use rocket::local::blocking::Client;
use rocket::State;

use rocket_csrf::{
    CSRF_ERROR_HEADER, CSRF_ERROR_VALUE, CSRF_HEADER, Csrf, CsrfForm, CsrfGuardError,
    CsrfToken, VerifiedXsrf, XSRF_COOKIE, XSRF_HEADER, XsrfToken,
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

#[get("/tokens")]
fn tokens(csrf: CsrfToken, xsrf: XsrfToken) -> rocket::serde::json::Json<(CsrfToken, XsrfToken)> {
    rocket::serde::json::Json((csrf, xsrf))
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
    let _ = &form.file;
    "uploaded"
}

#[post("/api")]
fn api(_xsrf: VerifiedXsrf) -> Status {
    Status::Created
}

#[post("/explicit-api")]
fn explicit_api(
    xsrf: Result<VerifiedXsrf, CsrfGuardError>,
    mutations: &State<AtomicUsize>,
) -> Result<Status, CsrfGuardError> {
    xsrf?;
    mutations.fetch_add(1, Ordering::SeqCst);
    Ok(Status::Created)
}

#[post("/swallow-option")]
fn swallow_option(_xsrf: Option<VerifiedXsrf>, mutations: &State<AtomicUsize>) -> Status {
    mutations.fetch_add(1, Ordering::SeqCst);
    Status::Forbidden
}

#[post("/swallow-result")]
fn swallow_result(
    _xsrf: Result<VerifiedXsrf, CsrfGuardError>,
    mutations: &State<AtomicUsize>,
) -> Status {
    mutations.fetch_add(1, Ordering::SeqCst);
    Status::Forbidden
}

#[get("/mutation-count")]
fn mutation_count(mutations: &State<AtomicUsize>) -> String {
    mutations.load(Ordering::SeqCst).to_string()
}

#[get("/application-forbidden")]
fn application_forbidden() -> Status {
    Status::Forbidden
}

#[get("/missing-fairing-response")]
fn missing_fairing_response() -> Result<Status, CsrfGuardError> {
    Err(CsrfGuardError::MissingFairing)
}

fn rocket() -> rocket::Rocket<rocket::Build> {
    rocket::build()
        .manage(AtomicUsize::new(0))
        .attach(Csrf::fairing())
        .mount("/", routes![
            token, tokens, xsrf, submit, forward_form, forward_body, multipart, upload, api,
            explicit_api, swallow_option, swallow_result, mutation_count, application_forbidden,
        ])
}

fn configured_rocket(key: u8) -> rocket::Rocket<rocket::Build> {
    let figment = rocket::Config::figment().merge(("secret_key", vec![key; 64]));
    rocket::custom(figment).attach(Csrf::fairing())
        .mount("/", routes![token, tokens, xsrf, submit, api])
}

fn limited_rocket() -> rocket::Rocket<rocket::Build> {
    let figment = rocket::Config::figment().merge(("limits.data-form", 512));
    rocket::custom(figment)
        .attach(Csrf::fairing())
        .mount("/", routes![token, upload])
}

#[test]
fn replicas_accept_the_same_tokens_and_private_session() {
    let issuer = Client::tracked(configured_rocket(42)).unwrap();
    let (form, header): (String, String) = issuer.get("/tokens").dispatch().into_json().unwrap();
    let cookies: Vec<_> = issuer.cookies().iter().cloned().collect();
    let replica = Client::untracked(configured_rocket(42)).unwrap();

    assert_eq!(replica.post("/submit").cookies(cookies.clone()).header(ContentType::Form)
        .body(format!("_authenticity_token={form}&username=alice"))
        .dispatch().status(), Status::Ok);
    assert_eq!(replica.post("/api").cookies(cookies)
        .header(Header::new(XSRF_HEADER, header))
        .dispatch().status(), Status::Created);
}

#[test]
fn tokens_and_sessions_survive_a_server_restart() {
    let (form, header, cookies) = {
        let issuer = Client::tracked(configured_rocket(42)).unwrap();
        let (form, header): (String, String) = issuer.get("/tokens").dispatch().into_json().unwrap();
        let cookies: Vec<_> = issuer.cookies().iter().cloned().collect();
        (form, header, cookies)
    };
    let restarted = Client::untracked(configured_rocket(42)).unwrap();
    assert_eq!(restarted.post("/submit").cookies(cookies.clone()).header(ContentType::Form)
        .body(format!("_authenticity_token={form}&username=alice"))
        .dispatch().status(), Status::Ok);
    assert_eq!(restarted.post("/api").cookies(cookies)
        .header(Header::new(XSRF_HEADER, header))
        .dispatch().status(), Status::Created);
}

#[test]
fn a_different_server_secret_rejects_tokens() {
    let issuer = Client::tracked(configured_rocket(42)).unwrap();
    let (form, header): (String, String) = issuer.get("/tokens").dispatch().into_json().unwrap();
    let cookies: Vec<_> = issuer.cookies().iter().cloned().collect();
    let other = Client::untracked(configured_rocket(43)).unwrap();
    assert_eq!(other.post("/submit").cookies(cookies.clone()).header(ContentType::Form)
        .body(format!("_authenticity_token={form}&username=alice"))
        .dispatch().status(), Status::Forbidden);
    assert_eq!(other.post("/api").cookies(cookies)
        .header(Header::new(XSRF_HEADER, header))
        .dispatch().status(), Status::Forbidden);
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
fn multipart_file_upload_rejects_invalid_token_before_file_fields() {
    let client = Client::tracked(rocket()).unwrap();
    let body = [
        "--X-BOUNDARY",
        r#"Content-Disposition: form-data; name="_authenticity_token""#,
        "",
        "invalid",
        "--X-BOUNDARY",
        r#"Content-Disposition: form-data; name="file"; filename="hello.txt""#,
        "Content-Type: text/plain",
        "",
        "hello",
        "--X-BOUNDARY--",
        "",
    ]
    .join("\r\n");

    let response = client.post("/upload")
        .header("multipart/form-data; boundary=X-BOUNDARY".parse::<ContentType>().unwrap())
        .body(body)
        .dispatch();
    assert_eq!(response.status(), Status::Forbidden);
    assert_eq!(response.headers().get_one(CSRF_ERROR_HEADER), None);
}

#[test]
fn multipart_file_upload_rejects_duplicate_token_before_file_fields() {
    let client = Client::tracked(rocket()).unwrap();
    let token = client.get("/token").dispatch().into_string().unwrap();
    let body = [
        "--X-BOUNDARY",
        r#"Content-Disposition: form-data; name="_authenticity_token""#,
        "",
        &token,
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

    let response = client.post("/upload")
        .header("multipart/form-data; boundary=X-BOUNDARY".parse::<ContentType>().unwrap())
        .body(body)
        .dispatch();
    assert_eq!(response.status(), Status::Forbidden);
    assert_eq!(response.headers().get_one(CSRF_ERROR_HEADER), None);
}

#[test]
fn truncated_multipart_is_not_passed_to_the_upload_handler() {
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
        "truncated",
    ]
    .join("\r\n");

    let response = client.post("/upload")
        .header("multipart/form-data; boundary=X-BOUNDARY".parse::<ContentType>().unwrap())
        .body(body)
        .dispatch();
    assert_ne!(response.status(), Status::Ok);
}

#[test]
fn configured_multipart_limit_rejects_oversized_upload() {
    let client = Client::tracked(limited_rocket()).unwrap();
    let token = client.get("/token").dispatch().into_string().unwrap();
    let small_body = [
        "--X-BOUNDARY",
        r#"Content-Disposition: form-data; name="_authenticity_token""#,
        "",
        &token,
        "--X-BOUNDARY",
        r#"Content-Disposition: form-data; name="file"; filename="small.txt""#,
        "Content-Type: text/plain",
        "",
        "small upload",
        "--X-BOUNDARY--",
        "",
    ]
    .join("\r\n");
    let accepted = client.post("/upload")
        .header("multipart/form-data; boundary=X-BOUNDARY".parse::<ContentType>().unwrap())
        .body(small_body)
        .dispatch();
    assert_eq!(accepted.status(), Status::Ok);

    let body = [
        "--X-BOUNDARY",
        r#"Content-Disposition: form-data; name="_authenticity_token""#,
        "",
        &token,
        "--X-BOUNDARY",
        r#"Content-Disposition: form-data; name="file"; filename="large.txt""#,
        "Content-Type: text/plain",
        "",
        &"x".repeat(4096),
        "--X-BOUNDARY--",
        "",
    ]
    .join("\r\n");

    let response = client.post("/upload")
        .header("multipart/form-data; boundary=X-BOUNDARY".parse::<ContentType>().unwrap())
        .body(body)
        .dispatch();
    assert_ne!(response.status(), Status::Ok);
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
    let cookie = response.cookies().get(XSRF_COOKIE).expect("readable XSRF cookie");
    assert_eq!(cookie.path(), Some("/"));
    assert_eq!(cookie.same_site(), Some(rocket::http::SameSite::Strict));
    assert_ne!(cookie.http_only(), Some(true));
    assert_ne!(cookie.secure(), Some(true));

    let private = response.cookies().get("__rocket_csrf_session_a")
        .expect("private session cookie");
    assert_eq!(private.path(), Some("/"));
    assert_eq!(private.same_site(), Some(rocket::http::SameSite::Strict));
    assert_eq!(private.http_only(), Some(true));
    assert!(private.expires().is_some());
}

#[test]
fn csrf_cookies_are_secure_on_https_requests() {
    let client = Client::tracked_secure(rocket()).unwrap();
    let response = client.get("/xsrf").dispatch();

    let xsrf = response.cookies().get(XSRF_COOKIE).expect("readable XSRF cookie");
    assert_eq!(xsrf.path(), Some("/"));
    assert_eq!(xsrf.same_site(), Some(rocket::http::SameSite::Strict));
    assert_ne!(xsrf.http_only(), Some(true));
    assert_eq!(xsrf.secure(), Some(true));

    let session = response.cookies().get("__rocket_csrf_session_a")
        .expect("private session cookie");
    assert_eq!(session.path(), Some("/"));
    assert_eq!(session.same_site(), Some(rocket::http::SameSite::Strict));
    assert_eq!(session.http_only(), Some(true));
    assert_eq!(session.secure(), Some(true));
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
    assert_eq!(response.headers().get_one(CSRF_ERROR_HEADER), None);
}

#[test]
fn header_xsrf_rejects_missing_header() {
    let client = Client::tracked(rocket()).unwrap();
    client.get("/xsrf").dispatch();

    let response = client.post("/api").dispatch();
    assert_eq!(response.status(), Status::Forbidden);
    assert_eq!(response.headers().get_one(CSRF_ERROR_HEADER), None);
}

#[test]
fn application_forbidden_is_not_misidentified_as_csrf_failure() {
    let client = Client::tracked(rocket()).unwrap();
    let response = client.get("/application-forbidden").dispatch();
    assert_eq!(response.status(), Status::Forbidden);
    assert_eq!(response.headers().get_one(CSRF_ERROR_HEADER), None);
}

#[test]
fn swallowed_guard_failures_that_mutate_are_not_marked_for_retry() {
    let client = Client::tracked(rocket()).unwrap();
    for path in ["/swallow-option", "/swallow-result"] {
        let response = client.post(path).dispatch();
        assert_eq!(response.status(), Status::Forbidden);
        assert_eq!(response.headers().get_one(CSRF_ERROR_HEADER), None);
    }

    assert_eq!(client.get("/mutation-count").dispatch().into_string().unwrap(), "2");
}

#[test]
fn explicit_missing_fairing_response_remains_internal_server_error() {
    let client = Client::tracked(
        rocket::build().mount("/", routes![missing_fairing_response]),
    ).unwrap();
    let response = client.get("/missing-fairing-response").dispatch();

    assert_eq!(response.status(), Status::InternalServerError);
    assert_eq!(response.headers().get_one(CSRF_ERROR_HEADER), None);
}

#[test]
fn explicit_csrf_responder_marks_rejection_before_side_effects() {
    let client = Client::tracked(rocket()).unwrap();
    let response = client.post("/explicit-api").dispatch();
    assert_eq!(response.status(), Status::Forbidden);
    assert_eq!(response.headers().get_one(CSRF_ERROR_HEADER), Some(CSRF_ERROR_VALUE));
    assert_eq!(client.get("/mutation-count").dispatch().into_string().unwrap(), "0");
}

#[test]
fn serialized_tokens_work_in_both_contexts_with_one_session() {
    let client = Client::tracked(rocket()).unwrap();
    let response = client.get("/tokens").dispatch();
    assert_eq!(response.headers().get_one("Cache-Control"), Some("no-store"));
    let (form, header): (String, String) = response.into_json().unwrap();

    assert_eq!(client.post("/submit").header(ContentType::Form)
        .body(format!("_authenticity_token={form}&username=alice"))
        .dispatch().status(), Status::Ok);
    assert_eq!(client.post("/api").header(Header::new(XSRF_HEADER, header.clone()))
        .dispatch().status(), Status::Created);

    // Header tokens must not be accepted as hidden form tokens either.
    assert_eq!(client.post("/submit").header(ContentType::Form)
        .body(format!("_authenticity_token={header}&username=alice"))
        .dispatch().status(), Status::Forbidden);
}

#[test]
fn issued_tokens_are_not_cacheable() {
    let client = Client::tracked(rocket()).unwrap();
    for path in ["/token", "/xsrf"] {
        let response = client.get(path).dispatch();
        assert_eq!(response.headers().get_one("Cache-Control"), Some("no-store"));
    }
    // Do not change cache policy on unrelated responses.
    assert!(client.get("/missing").dispatch().headers().get_one("Cache-Control").is_none());
}

#[rocket::async_test]
async fn concurrent_first_bootstraps_do_not_share_sessions_without_a_cookie() {
    use rocket::local::asynchronous::Client as AsyncClient;

    let client = AsyncClient::untracked(configured_rocket(42)).await.unwrap();
    let (first, second) = rocket::tokio::join!(
        client.get("/xsrf").dispatch(),
        client.get("/xsrf").dispatch(),
    );
    let first_token = first.cookies().get(XSRF_COOKIE).unwrap().value().to_string();
    let second_token = second.cookies().get(XSRF_COOKIE).unwrap().value().to_string();
    let second_cookies: Vec<_> = second.cookies().iter().cloned().collect();

    assert_ne!(first_token, second_token);
    let valid = client.post("/api").cookies(second_cookies.clone())
        .header(Header::new(XSRF_HEADER, second_token)).dispatch().await;
    assert_eq!(valid.status(), Status::Created);

    let mismatched = client.post("/api").cookies(second_cookies)
        .header(Header::new(XSRF_HEADER, first_token)).dispatch().await;
    assert_eq!(mismatched.status(), Status::Forbidden);
    assert_eq!(mismatched.headers().get_one(CSRF_ERROR_HEADER), None);
}

#[test]
fn tokens_cannot_be_replayed_in_another_browser() {
    let first = Client::tracked(rocket()).unwrap();
    let second = Client::tracked(rocket()).unwrap();
    let (form, header): (String, String) = first.get("/tokens").dispatch().into_json().unwrap();
    second.get("/tokens").dispatch();
    assert_eq!(second.post("/submit").header(ContentType::Form)
        .body(format!("_authenticity_token={form}&username=alice"))
        .dispatch().status(), Status::Forbidden);
    assert_eq!(second.post("/api").header(Header::new(XSRF_HEADER, header))
        .dispatch().status(), Status::Forbidden);
}

#[test]
fn duplicate_tokens_are_rejected() {
    let client = Client::tracked(rocket()).unwrap();
    let (form, header): (String, String) = client.get("/tokens").dispatch().into_json().unwrap();
    assert_eq!(client.post("/submit").header(ContentType::Form)
        .body(format!("_authenticity_token={form}&_authenticity_token={form}&username=alice"))
        .dispatch().status(), Status::Forbidden);
    for name in [XSRF_HEADER, CSRF_HEADER] {
        assert_eq!(client.post("/api")
            .header(Header::new(XSRF_HEADER, header.clone()))
            .header(Header::new(name, header.clone()))
            .dispatch().status(), Status::Forbidden);
    }
}

#[test]
fn ordinary_validation_errors_are_preserved() {
    let client = Client::tracked(rocket()).unwrap();
    let token = client.get("/token").dispatch().into_string().unwrap();
    assert_eq!(client.post("/submit").header(ContentType::Form)
        .body(format!("_authenticity_token={token}"))
        .dispatch().status(), Status::UnprocessableEntity);
}

#[test]
fn partial_configuration_uses_defaults_and_invalid_configuration_aborts() {
    for (key, value) in [("csrf.session_hours", 0), ("csrf.rotate.window", 24)] {
        let figment = rocket::Config::figment().merge((key, value));
        assert!(Client::debug(rocket::custom(figment).attach(Csrf::fairing())).is_err());
    }
    let figment = rocket::Config::figment().merge(("csrf.rotate.window", 2));
    assert!(Client::debug(rocket::custom(figment).attach(Csrf::fairing())
        .mount("/", routes![token])).is_ok());
}
