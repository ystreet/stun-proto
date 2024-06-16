// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub mod agent;

// reexport stun_types;
pub use stun_types as types;

#[derive(Clone)]
pub(crate) struct DebugWrapper<T>(&'static str, T);

impl<T> std::fmt::Debug for DebugWrapper<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl<T> std::ops::Deref for DebugWrapper<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.1
    }
}
impl<T> std::ops::DerefMut for DebugWrapper<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.1
    }
}
impl<T> DebugWrapper<T> {
    pub(crate) fn wrap(obj: T, name: &'static str) -> Self {
        Self(name, obj)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Once;
    use tracing_subscriber::EnvFilter;

    static TRACING: Once = Once::new();

    pub fn test_init_log() {
        TRACING.call_once(|| {
            if let Ok(filter) = EnvFilter::try_from_default_env() {
                tracing_subscriber::fmt().with_env_filter(filter).init();
            }
        });
    }
}
