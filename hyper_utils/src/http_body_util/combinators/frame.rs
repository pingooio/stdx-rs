use core::{future::Future, pin::Pin, task};

use hyper::body::Body;

#[must_use = "futures don't do anything unless polled"]
#[derive(Debug)]
/// Future that resolves to the next frame from a [`Body`].
pub struct Frame<'a, T: ?Sized>(pub(crate) &'a mut T);

impl<'a, T: Body + Unpin + ?Sized> Future for Frame<'a, T> {
    type Output = Option<Result<hyper::body::Frame<T::Data>, T::Error>>;

    fn poll(mut self: Pin<&mut Self>, ctx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        Pin::new(&mut self.0).poll_frame(ctx)
    }
}
