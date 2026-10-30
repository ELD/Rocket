# Native async trait migration

Rocket's minimum supported Rust version is now **1.92**. This release fixes
several lifetime-bound/`Send` proof cases that prevented the migration tracked
in [#2684](https://github.com/rwf2/Rocket/issues/2684).

## Remove the attribute from guard and pool implementations

These traits now use native async methods:

- `rocket::request::FromRequest`
- `rocket::data::FromData`
- `rocket::form::FromForm`
- `rocket::form::FromFormField`
- `rocket_db_pools::Pool`

Remove `#[rocket::async_trait]` from their implementations. Method bodies and
signatures usually stay unchanged. Form and database derives have been updated
automatically. Futures remain `Send`; request and data guard values themselves
are not required to be `Send`.

`Request::guard()` also returns an unboxed `Send` future now. Code explicitly
expecting a `BoxFuture` can use `Box::pin(request.guard::<T>())` at that boundary.

## Generic implementations and lifetime bounds

Rust 1.92 does not resolve every case of
[rust-lang/rust#100013](https://github.com/rust-lang/rust/issues/100013).
Nested generic implementations may still need an explicit `Send` bound on the
returned future so the compiler does not try to infer it through an opaque
async body. For example, a generic form wrapper can implement `push_data` as:

```rust
fn push_data(
    context: &mut Self::Context,
    field: rocket::form::DataField<'r, '_>,
) -> impl std::future::Future<Output = ()> + Send {
    async move {
        T::push_data(context, field).await;
    }
}
```

Rocket's generic implementations and generated form code make these bounds
explicit, without boxing. The internal `async_bound(Send)` helper performs this
transformation and now supports default method bodies as well as declarations.
Only `Send` is required of these futures, not `Sync`.

## Keep the attribute on dynamically dispatched traits

The following still use `async_trait` because Rocket stores trait objects for
them:

- `rocket::fairing::Fairing`
- `rocket::route::Handler`
- `rocket::catcher::Handler`
- `rocket::data::IoHandler`
- `rocket::tls::Resolver`

Keep the attribute on their implementations. The dependency and Rocket's public
re-export therefore remain available.

## Validation at the MSRV

CI resolves dependencies with Rust 1.92's MSRV fallback and tests core guards,
form derives, CSRF, WebSockets, template guards, and representative database
integrations. Its lockfile selects `scheduled-thread-pool` 0.2.7: version 0.2.8
has no MSRV metadata but requires `parking_lot` 0.13, which needs Rust 1.95.
This is a dependency-resolution constraint, separate from native async support.
