use std::fmt;
use std::marker::PhantomData;

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::WireError;

/// UTF-8 text of at most `N` bytes with no control characters. Peer names and
/// build ids use it: the bound lets a decoder refuse a long string before
/// allocating it, and the character rule keeps a peer's name from carrying
/// terminal escapes or line breaks into the CLI or a log.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundedStr<const N: usize>(String);

impl<const N: usize> BoundedStr<N> {
    pub fn new(text: &str) -> Result<Self, WireError> {
        check_str::<N>(text)?;
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn check_str<const N: usize>(text: &str) -> Result<(), WireError> {
    if text.len() > N {
        return Err(WireError::TooLong { max: N });
    }
    if text.chars().any(char::is_control) {
        return Err(WireError::Malformed);
    }
    Ok(())
}

impl<const N: usize> Serialize for BoundedStr<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de, const N: usize> Deserialize<'de> for BoundedStr<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrVisitor<const N: usize>;

        impl<const N: usize> Visitor<'_> for StrVisitor<N> {
            type Value = BoundedStr<N>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a string of at most {N} bytes")
            }

            // The decoder hands over a borrowed view, so the bound is checked
            // before the only allocation.
            fn visit_str<E: de::Error>(self, text: &str) -> Result<Self::Value, E> {
                BoundedStr::new(text).map_err(|_| E::custom("string out of bounds"))
            }
        }

        deserializer.deserialize_str(StrVisitor::<N>)
    }
}

/// A list of at most `N` items.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundedVec<T, const N: usize>(Vec<T>);

impl<T, const N: usize> BoundedVec<T, N> {
    pub fn new(items: Vec<T>) -> Result<Self, WireError> {
        if items.len() > N {
            return Err(WireError::TooLong { max: N });
        }
        Ok(Self(items))
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }
}

impl<T: Serialize, const N: usize> Serialize for BoundedVec<T, N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for BoundedVec<T, N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SeqVisitor<T, const N: usize>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for SeqVisitor<T, N> {
            type Value = BoundedVec<T, N>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a sequence of at most {N} items")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                // The declared length is peer-chosen: refuse it before reserving
                // anything, and never reserve more than the bound.
                let declared = seq.size_hint().unwrap_or(0);
                if declared > N {
                    return Err(de::Error::custom("sequence out of bounds"));
                }
                let mut items = Vec::with_capacity(declared);
                while let Some(item) = seq.next_element()? {
                    if items.len() >= N {
                        return Err(de::Error::custom("sequence out of bounds"));
                    }
                    items.push(item);
                }
                Ok(BoundedVec(items))
            }
        }

        deserializer.deserialize_seq(SeqVisitor::<T, N>(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use serde::de::value::{Error, SeqDeserializer};

    use super::*;

    #[test]
    fn si_23_bounded_vec_refuses_a_declared_length_before_reserving_for_it() {
        // postcard already caps its size hint at the bytes left, so this uses
        // a decoder that reports the peer's claim as is: reserving for it
        // would abort the process.
        let claims_everything = std::iter::repeat_n(0u8, usize::MAX);
        let result =
            BoundedVec::<u8, 64>::deserialize(SeqDeserializer::<_, Error>::new(claims_everything));
        assert!(result.is_err());

        let exact = SeqDeserializer::<_, Error>::new(std::iter::repeat_n(0u8, 64));
        assert_eq!(
            BoundedVec::<u8, 64>::deserialize(exact)
                .unwrap()
                .as_slice()
                .len(),
            64
        );
        let over = SeqDeserializer::<_, Error>::new(std::iter::repeat_n(0u8, 65));
        assert!(BoundedVec::<u8, 64>::deserialize(over).is_err());
    }

    #[test]
    fn names_refuse_control_characters() {
        assert!(BoundedStr::<32>::new("Alex").is_ok());
        assert_eq!(
            BoundedStr::<32>::new("evil\u{1b}[2J").unwrap_err(),
            WireError::Malformed
        );
        assert_eq!(
            BoundedStr::<32>::new("two\nlines").unwrap_err(),
            WireError::Malformed
        );
        assert_eq!(
            BoundedStr::<4>::new("toolong").unwrap_err(),
            WireError::TooLong { max: 4 }
        );
    }
}
