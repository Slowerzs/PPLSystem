//! This crate provide derive macros for [endian_codec] traits.
//!
//! Please refer to [endian_codec] to know how to set up.
//!
//! [endian_codec]:https://crates.io/crates/endian_codec

extern crate proc_macro;
use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{
    parse_macro_input, parse_quote, Data, DeriveInput, Fields, GenericParam, Generics,
    TypeParamBound,
};

mod attr;

#[derive(Clone, Copy)]
enum Endian {
    Big,
    Little,
    Mixed,
}

#[derive(Clone, Copy)]
enum Codec {
    Encode,
    Decode,
}

#[proc_macro_derive(PackedSize)]
pub fn derive_endian_size(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    // Parse the input tokens into a syntax tree.
    let input = parse_macro_input!(input as DeriveInput);

    // Used in the quasi-quotation below as `#name`.
    let name = input.ident;

    // Add a bound `T: EncodeLE` to every type parameter T.
    let generics = add_trait_bounds(input.generics, parse_quote!(PackedSize));
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let body = bytes_size(&input.data);

    let expanded = quote! {
        // The generated impl.
        impl #impl_generics PackedSize for #name #ty_generics #where_clause {
          const PACKED_LEN: usize = #body;
        }
    };

    // Hand the output tokens back to the compiler.
    proc_macro::TokenStream::from(expanded)
}

fn bytes_size(data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(ref fields) => {
                    // Expands to an expression like
                    //
                    //     0 + <self.x as PackedSize>::PACKED_LEN + <self.y as PackedSize>::PACKED_LEN
                    let recurse = fields.named.iter().map(|f| {
                        let ty = &f.ty;
                        quote_spanned! {f.span()=>
                            <#ty as PackedSize>::PACKED_LEN
                        }
                    });

                    quote! {
                        0  #(+ #recurse)*
                    }
                }
                Fields::Unnamed(ref fields) => {
                    // Expands to an expression like
                    //
                    //     0 + <self.0 as PackedSize>::PACKED_LEN + <self.1 as PackedSize>::PACKED_LEN
                    let recurse = fields.unnamed.iter().map(|f| {
                        let ty = &f.ty;
                        quote_spanned! {f.span()=>
                            <#ty as PackedSize>::PACKED_LEN
                        }
                    });
                    quote! {
                        0 #(+ #recurse)*
                    }
                }
                Fields::Unit => {
                    // Unit structs cannot own more than 0 bytes of heap memory.
                    quote!(0)
                }
            }
        }
        Data::Enum(_) | Data::Union(_) => unimplemented!(),
    }
}

#[proc_macro_derive(EncodeLE)]
pub fn derive_endian_ser_bytes(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    derive_endian_impl(input, Endian::Little, Codec::Encode)
}

#[proc_macro_derive(EncodeBE)]
pub fn derive_endian_de_bytes(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    derive_endian_impl(input, Endian::Big, Codec::Encode)
}

#[proc_macro_derive(EncodeME, attributes(endian))]
pub fn derive_endian_bytes(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    derive_endian_impl(input, Endian::Mixed, Codec::Encode)
}

#[proc_macro_derive(DecodeLE)]
pub fn derive_endian_le_de_bytes(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    derive_endian_impl(input, Endian::Little, Codec::Decode)
}

#[proc_macro_derive(DecodeBE)]
pub fn derive_endian_be_de_bytes(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    derive_endian_impl(input, Endian::Big, Codec::Decode)
}

#[proc_macro_derive(DecodeME, attributes(endian))]
pub fn derive_endian_me_de_bytes(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    derive_endian_impl(input, Endian::Mixed, Codec::Decode)
}

fn derive_endian_impl(
    input: proc_macro::TokenStream,
    endian: Endian,
    codec: Codec,
) -> proc_macro::TokenStream {
    // Parse the input tokens into a syntax tree.
    let input = parse_macro_input!(input as DeriveInput);

    // Used in the quasi-quotation below as `#name`.
    let name = input.ident;

    // Add a bound `T: (Big/Little/Mixed)Endian(Encode/Decode)` to every type parameter T.
    let generics = match codec {
        Codec::Encode => match endian {
            Endian::Little => add_trait_bounds(input.generics, parse_quote!(EncodeLE)),
            Endian::Big => add_trait_bounds(input.generics, parse_quote!(EncodeBE)),
            Endian::Mixed => add_trait_bounds(input.generics, parse_quote!(EncodeME)),
        },
        Codec::Decode => match endian {
            Endian::Little => add_trait_bounds(input.generics, parse_quote!(DecodeLE)),
            Endian::Big => add_trait_bounds(input.generics, parse_quote!(DecodeBE)),
            Endian::Mixed => add_trait_bounds(input.generics, parse_quote!(DecodeME)),
        },
    };

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // Generate an expression to sum up the heap size of each field.
    let body = codec_data_expands(&input.data, endian, codec);

    // The generated impl.
    let expanded = match codec {
        Codec::Encode => match endian {
            Endian::Little => quote! {
                impl #impl_generics EncodeLE for #name #ty_generics #where_clause {
                     #[inline]
                     fn encode_as_le_bytes(&self, bytes: &mut [u8]) -> usize {
                       #body
                       Self::PACKED_LEN
                     }
                }
            },
            Endian::Big => quote! {
                impl #impl_generics EncodeBE for #name #ty_generics #where_clause {
                     #[inline]
                     fn encode_as_be_bytes(&self, bytes: &mut [u8]) -> usize {
                       #body
                       Self::PACKED_LEN
                     }
                }
            },
            Endian::Mixed => quote! {
                impl #impl_generics EncodeME for #name #ty_generics #where_clause {
                     #[inline]
                     fn encode_as_me_bytes(&self, bytes: &mut [u8]) -> usize {
                       #body
                       Self::PACKED_LEN
                     }
                }
            },
        },
        Codec::Decode => match endian {
            Endian::Little => quote! {
                impl #impl_generics DecodeLE for #name #ty_generics #where_clause {
                     #[inline]
                     fn decode_from_le_bytes(bytes: &[u8]) -> Self {
                       Self { #body }
                     }
                }
            },
            Endian::Big => quote! {
                impl #impl_generics DecodeBE for #name #ty_generics #where_clause {
                     #[inline]
                     fn decode_from_be_bytes(bytes: &[u8]) -> Self {
                       Self { #body }
                     }
                }
            },
            Endian::Mixed => quote! {
                impl #impl_generics DecodeME for #name #ty_generics #where_clause {
                     #[inline]
                     fn decode_from_me_bytes(bytes: &[u8]) -> Self {
                       Self { #body }
                     }
                }
            },
        },
    };

    // Hand the output tokens back to the compiler.
    proc_macro::TokenStream::from(expanded)
}

use syn::{punctuated::Punctuated, token::Comma, Field};

fn codec_fields(fields: &Punctuated<Field, Comma>, endian: Endian, codec: Codec) -> TokenStream {
    let mut beg_offset = quote! { 0 };
    let mut recurse = vec![];
    for field in fields.iter() {
        let name = &field.ident;
        let ty = &field.ty;
        let struct_size = quote! { <#ty as PackedSize>::PACKED_LEN };
        let end_offset = quote! { #beg_offset + #struct_size };
        let bytes_slice = quote! { bytes[#beg_offset..#end_offset] };
        match codec {
            Codec::Encode => match endian {
                Endian::Little => recurse.push(quote_spanned! {field.span()=>
                    debug_assert_eq!(#struct_size, #bytes_slice.len());
                    EncodeLE::encode_as_le_bytes(&self.#name, &mut #bytes_slice);
                }),
                Endian::Big => recurse.push(quote_spanned! {field.span()=>
                    debug_assert_eq!(#struct_size, #bytes_slice.len());
                    EncodeBE::encode_as_be_bytes(&self.#name, &mut #bytes_slice);
                }),
                Endian::Mixed => {
                    let filed_endian = attr::endian_from_attribute(&field.attrs);

                    let r = match filed_endian {
                        Some(Endian::Little) => quote_spanned! {field.span()=>
                            debug_assert_eq!(#struct_size, #bytes_slice.len());
                            EncodeLE::encode_as_le_bytes(&self.#name, &mut #bytes_slice);
                        },
                        Some(Endian::Big) => quote_spanned! {field.span()=>
                            debug_assert_eq!(#struct_size, #bytes_slice.len());
                            EncodeBE::encode_as_be_bytes(&self.#name, &mut #bytes_slice);
                        },
                        Some(Endian::Mixed) => unimplemented!(),
                        None => quote_spanned! {field.span()=>
                          debug_assert_eq!(#struct_size, #bytes_slice.len());
                          EncodeME::encode_as_me_bytes(&self.#name, &mut #bytes_slice);
                        },
                    };
                    recurse.push(r)
                }
            },
            Codec::Decode => match endian {
                Endian::Little => recurse.push(quote_spanned! {field.span()=>
                    #name: DecodeLE::decode_from_le_bytes(& #bytes_slice),
                }),
                Endian::Big => recurse.push(quote_spanned! {field.span()=>
                    #name: DecodeBE::decode_from_be_bytes(& #bytes_slice),
                }),
                Endian::Mixed => {
                    let filed_endian = attr::endian_from_attribute(&field.attrs);

                    let r = match filed_endian {
                        Some(Endian::Little) => quote_spanned! {field.span()=>
                            #name: DecodeLE::decode_from_le_bytes(& #bytes_slice),
                        },
                        Some(Endian::Big) => quote_spanned! {field.span()=>
                            #name: DecodeBE::decode_from_be_bytes(& #bytes_slice),
                        },
                        Some(Endian::Mixed) => unimplemented!(),
                        None => quote_spanned! {field.span()=>
                          #name: DecodeME::decode_from_me_bytes(& #bytes_slice),
                        },
                    };
                    recurse.push(r)
                }
            },
        }
        beg_offset = quote! { #beg_offset + #struct_size }
    }

    quote! {
        #(#recurse)*
    }
}

fn codec_data_expands(data: &Data, endian: Endian, codec: Codec) -> TokenStream {
    // this also contains `bytes` variable
    match *data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(ref fields) => codec_fields(&fields.named, endian, codec),
                Fields::Unnamed(ref fields) => codec_fields(&fields.unnamed, endian, codec),
                Fields::Unit => {
                    // Unit structs cannot own more than 0 bytes of heap memory.
                    quote!(0)
                }
            }
        }
        Data::Enum(_) | Data::Union(_) => unimplemented!(),
    }
}

// Add a bound `T: trait_bound` to every type parameter T.
fn add_trait_bounds(mut generics: Generics, trait_bound: TypeParamBound) -> Generics {
    for param in &mut generics.params {
        if let GenericParam::Type(ref mut type_param) = *param {
            type_param.bounds.push(trait_bound.clone());
        }
    }
    generics
}
