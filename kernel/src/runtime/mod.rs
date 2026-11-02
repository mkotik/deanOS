pub mod executor;
pub mod sleep;

/// Single-core `Sync` shim: the executor is single-threaded and ISRs never
/// touch wrapped state, so RefCell's runtime borrow check suffices.
pub struct SingleCore<T>(pub core::cell::RefCell<T>);
unsafe impl<T> Sync for SingleCore<T> {}

impl<T> SingleCore<T> {
    pub const fn new(v: T) -> Self {
        SingleCore(core::cell::RefCell::new(v))
    }
}
