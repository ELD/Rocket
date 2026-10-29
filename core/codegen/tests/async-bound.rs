use std::cell::Cell;

use rocket::async_bound;

trait Defaults: Sync {
    #[async_bound(Send)]
    async fn required(&self) -> usize;

    #[async_bound(Send)]
    async fn default_value(&self, early: bool) -> Result<usize, ()> {
        if early {
            return Ok(7);
        }

        let value = Ok::<_, ()>(self.required().await)?;
        rocket::tokio::task::yield_now().await;
        Ok(value + 1)
    }
}

impl Defaults for () {
    async fn required(&self) -> usize { 10 }
}

// A default method taking &mut self only needs Self: Send, not Self: Sync.
trait Mutable: Send {
    #[async_bound(Send)]
    async fn increment(&mut self) -> usize;

    #[async_bound(Send)]
    async fn twice(&mut self) -> usize {
        self.increment().await;
        self.increment().await
    }
}

impl Mutable for Cell<usize> {
    async fn increment(&mut self) -> usize {
        rocket::tokio::task::yield_now().await;
        self.set(self.get() + 1);
        self.get()
    }
}

fn assert_send<T: Send>(value: T) -> T { value }

#[rocket::async_test]
async fn default_method_bodies_are_futures() {
    assert_eq!(assert_send(().default_value(true)).await, Ok(7));
    assert_eq!(assert_send(().default_value(false)).await, Ok(11));
    assert_eq!(assert_send(Cell::new(0).twice()).await, 2);
}
