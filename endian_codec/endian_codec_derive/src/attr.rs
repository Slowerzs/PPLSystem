// handle parse of #[endian = "..."]

use crate::Endian;
use syn::{Attribute, Lit, Meta};

pub(crate) fn endian_from_attribute(attrs: &[Attribute]) -> Option<Endian> {
    let mut endian = None;
    for attr in attrs {
        if !attr.path.is_ident("endian") {
            // this is not #[endian..] attribute
            continue;
        }

        if let Ok(meta) = attr.parse_meta() {
            match meta {
                Meta::Path(_) => unimplemented!(),
                Meta::List(_) => unimplemented!(),
                Meta::NameValue(nv) => {
                    assert!(nv.path.is_ident("endian"));
                    assert!(endian.is_none()); // FIXME span error - only one endian can be used!
                    endian = Some(match nv.lit {
                        Lit::Str(v) => match v.value().as_ref() {
                            "le" | "little" => Endian::Little,
                            "be" | "big" => Endian::Big,
                            "native" => unimplemented!(),
                            "custom" => unimplemented!(),
                            _ => unimplemented!(),
                        },
                        _ => unimplemented!(),
                    });
                }
            }
        } else {
            unimplemented!()
        }
    }
    endian
}
