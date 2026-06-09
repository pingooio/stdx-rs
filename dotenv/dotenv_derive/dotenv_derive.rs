use proc_macro::TokenStream;
use proc_macro2::Ident;
use quote::quote;
use syn::{
    Data, DeriveInput, Expr, Fields, LitStr, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

#[proc_macro_derive(FromEnv, attributes(env))]
pub fn derive_from_env(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => panic!("FromEnv only supports structs with named fields"),
        },
        _ => panic!("FromEnv only supports structs"),
    };

    let field_assignments: Vec<_> = fields
        .iter()
        .map(|f| {
            let field_name = &f.ident;
            let field_name_str = field_name.as_ref().unwrap().to_string();
            let screaming = to_screaming_snake(&field_name_str);
            let ty = &f.ty;

            let attrs: Vec<EnvAttr> = f
                .attrs
                .iter()
                .filter(|a| a.path().is_ident("env"))
                .map(|a| a.parse_args::<EnvAttr>().unwrap())
                .collect();

            let attr = attrs.first();

            match attr {
                // #[env(rename = "VAR")] — explicit name, FromEnvValue parsing
                Some(EnvAttr {
                    rename: Some(var_name),
                    default: None,
                    with: None,
                }) => {
                    let var = var_name.value();
                    quote! {
                        #field_name: {
                            let val = ::std::env::var(#var)
                                .map_err(|_| ::dotenv::FromEnvError::missing(#var))?;
                            <#ty as ::dotenv::FromEnvValue>::from_env_value(val.clone())
                                .map_err(|e| ::dotenv::FromEnvError::invalid(#var, val, e))?
                        }
                    }
                }
                // #[env(rename = "VAR", default)] — explicit name, fallback to Default::default()
                Some(EnvAttr {
                    rename: Some(var_name),
                    default: Some(DefaultKind::Standard),
                    with: None,
                }) => {
                    let var = var_name.value();
                    quote! {
                        #field_name: {
                            match ::std::env::var(#var) {
                                Ok(val) => <#ty as ::dotenv::FromEnvValue>::from_env_value(val.clone())
                                    .map_err(|e| ::dotenv::FromEnvError::invalid(#var, val, e))?,
                                Err(_) => ::std::default::Default::default(),
                            }
                        }
                    }
                }
                // #[env(rename = "VAR", default = EXPR)] — explicit name, fallback to expr
                Some(EnvAttr {
                    rename: Some(var_name),
                    default: Some(DefaultKind::Expr(expr)),
                    with: None,
                }) => {
                    let var = var_name.value();
                    quote! {
                        #field_name: {
                            match ::std::env::var(#var) {
                                Ok(val) => <#ty as ::dotenv::FromEnvValue>::from_env_value(val.clone())
                                    .map_err(|e| ::dotenv::FromEnvError::invalid(#var, val, e))?,
                                Err(_) => #expr,
                            }
                        }
                    }
                }
                // #[env(rename = "VAR", with = "func")] — explicit name, custom parser
                Some(EnvAttr {
                    rename: Some(var_name),
                    default: None,
                    with: Some(func),
                }) => {
                    let var = var_name.value();
                    let func = Ident::new(&func.value(), proc_macro2::Span::call_site());
                    quote! {
                        #field_name: {
                            let val = ::std::env::var(#var)
                                .map_err(|_| ::dotenv::FromEnvError::missing(#var))?;
                            #func(#var, &val)?
                        }
                    }
                }
                // #[env(with = "func")] — default naming, custom parser
                Some(EnvAttr {
                    rename: None,
                    default: None,
                    with: Some(func),
                }) => {
                    let func = Ident::new(&func.value(), proc_macro2::Span::call_site());
                    quote! {
                        #field_name: {
                            let var_name = ::std::format!("{}{}", prefix, #screaming);
                            let val = ::std::env::var(&var_name)
                                .map_err(|_| ::dotenv::FromEnvError::missing(var_name.clone()))?;
                            #func(&var_name, &val)?
                        }
                    }
                }
                // #[env(default)] — unconditional Default::default()
                // Does NOT read the env var; the default is used unconditionally.
                // For reading + fallback, combine with rename: #[env(rename = "VAR", default)]
                Some(EnvAttr {
                    rename: None,
                    default: Some(DefaultKind::Standard),
                    with: None,
                }) => {
                    quote! {
                        #field_name: ::std::default::Default::default()
                    }
                }
                // #[env(default = EXPR)] — unconditional expression
                // Does NOT read the env var; the expression is used unconditionally.
                Some(EnvAttr {
                    rename: None,
                    default: Some(DefaultKind::Expr(expr)),
                    with: None,
                }) => {
                    quote! {
                        #field_name: #expr
                    }
                }
                // #[env()] or #[env] with no args — same as no attribute
                Some(EnvAttr {
                    rename: None,
                    default: None,
                    with: None,
                }) => {
                    quote! {
                        #field_name: <#ty as ::dotenv::FromEnvAuto>::from_env_auto(
                            &::std::format!("{}{}_", prefix, #screaming),
                            &::std::format!("{}{}", prefix, #screaming),
                        )?
                    }
                }
                // No attribute → auto-dispatch via FromEnvAuto
                //   - If the type implements FromEnv (nested struct): calls from_env_with_prefix
                //   - Otherwise (leaf type like String, u32): reads env var + FromStr
                None => {
                    quote! {
                        #field_name: <#ty as ::dotenv::FromEnvAuto>::from_env_auto(
                            &::std::format!("{}{}_", prefix, #screaming),
                            &::std::format!("{}{}", prefix, #screaming),
                        )?
                    }
                }
                // Invalid combination of attributes
                _ => {
                    panic!(
                        "invalid `#[env(...)]` attributes on field `{}`: supported are \
                     `#[env(rename = \"...\")]`, `#[env(rename = \"...\", with = \"...\")]`, \
                     `#[env(with = \"...\")]`, `#[env(default)]`, \
                     `#[env(default = ...)]`, or no attribute",
                        field_name_str
                    );
                }
            }
        })
        .collect();

    let expanded = quote! {
        #[automatically_derived]
        impl ::dotenv::FromEnv for #name {
            fn from_env_with_prefix(prefix: &str) -> ::std::result::Result<Self, ::dotenv::FromEnvError> {
                Ok(Self {
                    #(#field_assignments,)*
                })
            }
        }
    };

    TokenStream::from(expanded)
}

fn to_screaming_snake(s: &str) -> String {
    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if i > 0 && chars[i].is_ascii_uppercase() {
            let prev_lower = chars[i - 1].is_ascii_lowercase();
            let next_lower = i + 1 < chars.len() && chars[i + 1].is_ascii_lowercase();
            if prev_lower || (next_lower && i > 0 && chars[i - 1].is_ascii_uppercase()) {
                result.push('_');
            }
        }
        result.push(chars[i].to_ascii_uppercase());
        i += 1;
    }
    result
}

struct EnvAttr {
    rename: Option<LitStr>,
    default: Option<DefaultKind>,
    with: Option<LitStr>,
}

enum DefaultKind {
    Standard,
    Expr(Expr),
}

impl Parse for EnvAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut rename = None;
        let mut default = None;
        let mut with = None;

        while !input.is_empty() {
            let ident: syn::Ident = input.parse()?;
            match ident.to_string().as_str() {
                "rename" => {
                    input.parse::<Token![=]>()?;
                    rename = Some(input.parse()?);
                }
                "default" => {
                    if input.peek(Token![=]) {
                        input.parse::<Token![=]>()?;
                        default = Some(DefaultKind::Expr(input.parse()?));
                    } else {
                        default = Some(DefaultKind::Standard);
                    }
                }
                "with" => {
                    input.parse::<Token![=]>()?;
                    with = Some(input.parse()?);
                }
                other => {
                    return Err(syn::Error::new(ident.span(), format!("unknown env attribute: `{other}`")));
                }
            }
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(EnvAttr {
            rename,
            default,
            with,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_screaming_snake() {
        assert_eq!(to_screaming_snake("url"), "URL");
        assert_eq!(to_screaming_snake("my_field"), "MY_FIELD");
        assert_eq!(to_screaming_snake("myField"), "MY_FIELD");
        assert_eq!(to_screaming_snake("XMLParser"), "XML_PARSER");
        assert_eq!(to_screaming_snake("database_url"), "DATABASE_URL");
        assert_eq!(to_screaming_snake("db"), "DB");
        assert_eq!(to_screaming_snake("a"), "A");
        assert_eq!(to_screaming_snake(""), "");
    }
}
