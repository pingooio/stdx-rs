use std::any::Any;

use crate::common::{types::Type, value::Val};

pub struct Float(f64);

impl Val for Float {
    fn get_type(&self) -> Type<'_> {
        super::FLOAT_TYPE
    }

    fn into_inner(self) -> Box<dyn Any> {
        Box::new(self.0)
    }
}

impl From<Float> for f64 {
    fn from(value: Float) -> Self {
        value.0
    }
}

impl From<f64> for Float {
    fn from(value: f64) -> Self {
        Self(value)
    }
}
