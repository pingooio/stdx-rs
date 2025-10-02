use std::{any::Any, time::SystemTime};

use crate::common::{types::Type, value::Val};

pub struct Timestamp(SystemTime);

impl Val for Timestamp {
    fn get_type(&self) -> Type<'_> {
        super::TIMESTAMP_TYPE
    }

    fn into_inner(self) -> Box<dyn Any> {
        Box::new(self.0)
    }
}

impl From<SystemTime> for Timestamp {
    fn from(system_time: SystemTime) -> Self {
        Self(system_time)
    }
}

impl From<Timestamp> for SystemTime {
    fn from(timestamp: Timestamp) -> Self {
        timestamp.0
    }
}
