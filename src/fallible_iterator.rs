
use std::marker::PhantomData;

use windows::{
    core::{
        Error, Result,
    },
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub trait FallibleIterator {
    type Item;

    fn next(&mut self) -> Result<Option<Self::Item>>;

    fn for_each( mut self, mut f: impl FnMut(Self::Item) -> Result<()> ) -> Result<()> where Self: Sized {
        while let Some(item) = self.next()? {
            f(item)?;
        }

        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct Empty<I: FallibleIterator> {
    _ph: PhantomData<I>,
}
 
impl<I: FallibleIterator> Empty<I> {
    pub fn new() -> Self {
        Self {
            _ph: PhantomData,
        }
    }
}

impl<I> FallibleIterator for Empty<I>
where
    I: FallibleIterator, 
{
    type Item = I::Item;

    #[inline(always)]
    fn next(&mut self) -> Result<Option<Self::Item>> {
        Ok(None)
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct Filter<I, F>
where
    I: FallibleIterator, 
    F: Fn(&I::Item) -> Result<bool>
{
    inner: I,
    f: F,
}

impl<I, F> Filter<I, F> 
where
    I: FallibleIterator, 
    F: Fn(&I::Item) -> Result<bool>
{
    pub fn new( inner: I, f: F ) -> Self {
        Self {
            inner,
            f
        }
    }
}

impl<I, F> FallibleIterator for Filter<I, F>
where
    I: FallibleIterator, 
    F: Fn(&I::Item) -> Result<bool>
{
    type Item = I::Item;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        while let Some(item) = self.inner.next()? {
            if (self.f)(&item)? {
                return Ok(Some(item));
            };
        }

        Ok(None)
    }
}
