use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Meta, parse_macro_input};

#[proc_macro_derive(FromRow, attributes(pg))]
pub fn derive_from_row(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let rename_all = get_rename_all(&input.attrs);

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => panic!("FromRow only supports structs with named fields"),
        },
        _ => panic!("FromRow only supports structs"),
    };

    let field_assignments: Vec<_> = fields
        .iter()
        .map(|f| {
            let field_name = &f.ident;
            let field_name_str = field_name.as_ref().unwrap().to_string();

            let (column_name, default) = parse_field_attrs(&f.attrs);
            let column_name = column_name.unwrap_or_else(|| match rename_all.as_deref() {
                Some("camelCase") => to_camel_case(&field_name_str),
                Some("PascalCase") => to_pascal_case(&field_name_str),
                Some("lowercase") => field_name_str.to_lowercase(),
                Some("UPPERCASE") => field_name_str.to_uppercase(),
                _ => to_snake_case(&field_name_str),
            });

            let ty = &f.ty;

            if default {
                quote! {
                    #field_name: row.try_get::<#ty>(#column_name).unwrap_or_default(),
                }
            } else {
                quote! {
                    #field_name: row.try_get::<#ty>(#column_name)?,
                }
            }
        })
        .collect();

    let expanded = quote! {
        impl ::pg::FromRow for #name {
            fn from_row(row: &::pg::Row) -> std::result::Result<Self, ::pg::PgError> {
                Ok(Self {
                    #(#field_assignments)*
                })
            }
        }
    };

    TokenStream::from(expanded)
}

fn get_rename_all(attrs: &[syn::Attribute]) -> Option<String> {
    for attr in attrs {
        if attr.path().is_ident("pg") {
            if let Ok(meta) = attr.parse_args::<Meta>() {
                match meta {
                    Meta::List(list) => {
                        let inner = list.tokens.to_string();
                        let inner = inner.trim().trim_start_matches('(').trim_end_matches(')');
                        if let Some(val) = inner.strip_prefix("rename_all = ") {
                            return Some(val.trim().trim_matches('"').to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    None
}

fn parse_field_attrs(attrs: &[syn::Attribute]) -> (Option<String>, bool) {
    let mut column = None;
    let mut default = false;

    for attr in attrs {
        if attr.path().is_ident("pg") {
            let inner = attr.meta.require_list().unwrap().tokens.to_string();
            for part in inner.split(',') {
                let part = part.trim();
                if part == "default" {
                    default = true;
                } else if let Some(val) = part.strip_prefix("column = ") {
                    column = Some(val.trim().trim_matches('"').to_string());
                }
            }
        }
    }

    (column, default)
}

fn to_camel_case(s: &str) -> String {
    let mut result = String::new();
    let mut upper = false;
    for c in s.chars() {
        if c == '_' {
            upper = true;
        } else if upper {
            result.push(c.to_ascii_uppercase());
            upper = false;
        } else {
            result.push(c);
        }
    }
    result
}

fn to_pascal_case(s: &str) -> String {
    let camel = to_camel_case(s);
    let mut chars = camel.chars();
    match chars.next() {
        Some(c) => c.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            result.push('_');
        }
        result.push(c.to_ascii_lowercase());
    }
    result
}
