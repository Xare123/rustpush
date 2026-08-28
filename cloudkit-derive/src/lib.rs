use deluxe::Flag;
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, LitStr};

#[derive(deluxe::ExtractAttributes)]
#[deluxe(attributes(cloudkit_record))]
struct CloudKitRecordAttributes {
    r#type: String,
    encrypted: Flag,
    rename_all: Option<String>,
}

#[derive(deluxe::ExtractAttributes)]
#[deluxe(attributes(cloudkit))]
struct CloudKitAttributes {
    rename: Option<String>,
    encrypted: Flag,
    unencrypted: Flag,
    skip: Flag,
}

fn snake_to_camel(s: &str) -> String {
    let mut camel = String::new();
    let mut upper_next = false;

    for c in s.chars() {
        if c == '_' {
            upper_next = true;
        } else if upper_next {
            camel.push_str(&c.to_uppercase().to_string());
            upper_next = false;
        } else {
            camel.push(c);
        }
    }

    camel
}

#[proc_macro_derive(CloudKitRecord, attributes(cloudkit_record, cloudkit))]
pub fn cloudkitrecord_derive(input: TokenStream) -> TokenStream {
    let mut input = parse_macro_input!(input as DeriveInput);

    let CloudKitRecordAttributes {
        r#type,
        encrypted: record_encrypted,
        rename_all,
    } = deluxe::extract_attributes(&mut input).unwrap();

    let name = input.ident;

    let Data::Struct(s) = input.data else {
        panic!("CloudKit records must be structs!")
    };

    let field_count = s.fields.len();

    let mut fields: Vec<proc_macro2::TokenStream> = vec![];
    let mut read_fields: Vec<proc_macro2::TokenStream> = vec![];
    for mut field in s.fields {
        let CloudKitAttributes {
            rename,
            encrypted,
            unencrypted,
            skip,
        } = deluxe::extract_attributes(&mut field).unwrap();

        if skip.into() {
            continue;
        }
        let mut is_encrypted: bool = record_encrypted.into();
        if encrypted.into() {
            is_encrypted = true;
        }
        if unencrypted.into() {
            is_encrypted = false;
        }

        let ident = field.ident.unwrap();
        let name = rename.unwrap_or_else(|| {
            if let Some(rename_all) = &rename_all {
                let name = ident.to_string();
                return if rename_all == "camelCase" {
                    snake_to_camel(&name)
                } else {
                    panic!("unknown rename {}", rename_all)
                };
            }

            ident.to_string()
        });
        let name_lit = LitStr::new(&name, Span::call_site());
        if is_encrypted {
            fields.push(quote! {
                {
                    let e = encryptor.expect("No encryption key provided for record decryption!");
                    if let Some(field) = cloudkit_proto::CloudKitEncryptedValue::to_value_encrypted(&self.#ident, e, #name_lit) {
                        results.push(cloudkit_proto::record::Field {
                            identifier: Some(cloudkit_proto::record::field::Identifier {
                                name: Some(#name.to_string())
                            }),
                            value: Some(field)
                        });
                    }
                }
            });
            read_fields.push(quote! {
                #name => {
                    let e = encryptor.ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "CloudKit record decryption key unavailable",
                        )
                    })?;
                    let field_value = data.value.as_ref().ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "CloudKit record field missing value",
                        )
                    })?;
                    default.#ident = cloudkit_proto::CloudKitEncryptedValue::from_value_encrypted(
                        field_value,
                        e,
                        #name_lit,
                    )
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "CloudKit record field value is invalid",
                        )
                    })?;
                }
            })
        } else {
            fields.push(quote! {
                if let Some(field) = cloudkit_proto::CloudKitValue::to_value(&self.#ident) {
                    results.push(cloudkit_proto::record::Field {
                        identifier: Some(cloudkit_proto::record::field::Identifier {
                            name: Some(#name.to_string())
                        }),
                        value: Some(field)
                    });
                }
            });
            read_fields.push(quote! {
                #name => {
                    let field_value = data.value.as_ref().ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "CloudKit record field missing value",
                        )
                    })?;
                    default.#ident = cloudkit_proto::CloudKitValue::from_value(field_value)
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "CloudKit record field value is invalid",
                            )
                        })?;
                }
            })
        }
    }

    quote! {
        impl #name {
            pub fn try_from_record(
                value: &[cloudkit_proto::record::Field],
            ) -> std::io::Result<Self> {
                struct NoCloudKitEncryptor;

                impl cloudkit_proto::CloudKitEncryptor for NoCloudKitEncryptor {
                    fn encrypt_data(&self, _: &[u8], _: &str) -> Vec<u8> {
                        Vec::new()
                    }

                    fn decrypt_data(&self, _: &[u8], _: &str) -> Vec<u8> {
                        Vec::new()
                    }
                }

                Self::try_from_record_encrypted(value, None::<&NoCloudKitEncryptor>)
            }

            pub fn try_from_record_encrypted(
                value: &[cloudkit_proto::record::Field],
                encryptor: Option<&impl cloudkit_proto::CloudKitEncryptor>,
            ) -> std::io::Result<Self> {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut default = Self::default();

                    for data in value {
                        let identifier = data.identifier.as_ref().ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "CloudKit record field missing identifier",
                            )
                        })?;
                        let field_name = identifier.name.as_ref().ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "CloudKit record field identifier missing name",
                            )
                        })?;

                        match field_name.as_str() {
                            #(#read_fields)*
                            _unk => info!("Unknown CloudKit record field"),
                        }
                    }

                    Ok(default)
                }))
                .unwrap_or_else(|_| {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "CloudKit record parsing failed",
                    ))
                })
            }
        }

        impl cloudkit_proto::CloudKitRecord for #name {
            fn to_record_encrypted(&self, encryptor: Option<&impl CloudKitEncryptor>) -> Vec<cloudkit_proto::record::Field> {
                let mut results = Vec::with_capacity(#field_count);

                #(#fields)*

                results
            }

            fn from_record_encrypted(value: &[cloudkit_proto::record::Field], encryptor: Option<&impl CloudKitEncryptor>) -> Self
                where
                    Self: Sized {
                Self::try_from_record_encrypted(value, encryptor).unwrap_or_default()
            }

            fn record_type() -> &'static str {
                #r#type
            }
        }
    }.into()
}
