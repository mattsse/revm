use crate::error::ExitError;
use primitive_types::H256;

use super::STACK_LIMIT;

/// EVM stack.
#[derive(Clone, Debug)]
pub struct Stack {
    data: [H256; STACK_LIMIT],
    index: usize,
}

impl Stack {
    /// Create a new stack with given limit.
    pub fn new() -> Self {
        Self {
            data: [H256::zero(); STACK_LIMIT],
            index: 0,
        }
    }

    #[inline]
    /// Stack length.
    pub fn len(&self) -> usize {
        self.index
    }

    #[inline]
    /// Whether the stack is empty.
    pub fn is_empty(&self) -> bool {
        self.index == 0
    }

    #[inline]
    /// Stack data.
    pub fn data(&self) -> &[H256] {
        &self.data
    }

    #[inline]
    /// Pop a value from the stack. If the stack is already empty, returns the
    /// `StackUnderflow` error.
    pub fn pop(&mut self) -> Result<H256, ExitError> {
        if self.index == 0 {
            Err(ExitError::StackUnderflow)
        } else {
            self.index -= 1;
            let out = Ok(core::mem::take(&mut self.data[self.index]));
            out
        }
    }

    #[inline]
    /// Push a new value into the stack. If it will exceed the stack limit,
    /// returns `StackOverflow` error and leaves the stack unchanged.
    pub fn push(&mut self, value: H256) -> Result<(), ExitError> {
        if self.index > STACK_LIMIT-1 {
            return Err(ExitError::StackOverflow);
        }
        self.data[self.index] = value;
        self.index += 1;
        Ok(())
    }

    #[inline]
    /// Peek a value at given index for the stack, where the top of
    /// the stack is at index `0`. If the index is too large,
    /// `StackError::Underflow` is returned.
    pub fn peek(&self, no_from_top: usize) -> Result<H256, ExitError> {
        if no_from_top < self.index {
            Ok(self.data[self.index - no_from_top - 1])
        } else {
            Err(ExitError::StackUnderflow)
        }
    }

    #[inline]
    /// Set a value at given index for the stack, where the top of the
    /// stack is at index `0`. If the index is too large,
    /// `StackError::Underflow` is returned.
    pub fn set(&mut self, no_from_top: usize, val: H256) -> Result<(), ExitError> {
        if no_from_top < self.index {
            self.data[self.index - no_from_top - 1] = val;
            Ok(())
        } else {
            Err(ExitError::StackUnderflow)
        }
    }
}
