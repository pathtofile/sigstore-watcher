use clap::Parser;
use reqwest::blocking::Client;
use serde_json::{json, Value};
use x509_parser::oid_registry::asn1_rs::oid;
use x509_parser::prelude::*;

use std::error::Error;
use std::{thread, time};

use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;

// Setup Commandline args
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Polling Interval
    #[arg(short, long, default_value_t = 3)]
    interval: u64,
}

fn log_data(log_index: u64, hash: &str, cert: &X509Certificate) -> Result<(), Box<dyn Error>> {
    // println!("{:#?}", cert);

    let mut j = json!({
        "Log Index": log_index,
        "Hash": hash
    });

    let tbs = &cert.tbs_certificate;
    for ext in tbs.extensions() {
        if ext.oid == oid!(2.5.29 .17) {
            // Subject alt name
            if let ParsedExtension::SubjectAlternativeName(ext) = ext.parsed_extension() {
                let names = &ext.general_names;
                for n in names {
                    match n {
                        GeneralName::RFC822Name(n)
                        | GeneralName::URI(n)
                        | GeneralName::DNSName(n) => {
                            j["Subject"] = json!(n);
                        }
                        _ => {
                            j["Subject"] = json!(n.to_string());
                        }
                    }
                }
            }
        } else if ext.oid == oid!(1.3.6 .1 .4 .1 .57264 .1 .1) {
            if let Ok(val) = std::str::from_utf8(ext.value) {
                j["OIDC Issuer"] = json!(val);
            }
        } else if ext.oid == oid!(1.3.6 .1 .4 .1 .57264 .1 .2) {
            if let Ok(val) = std::str::from_utf8(ext.value) {
                j["GitHub Workflow Trigger"] = json!(val);
            }
        } else if ext.oid == oid!(1.3.6 .1 .4 .1 .57264 .1 .3) {
            if let Ok(val) = std::str::from_utf8(ext.value) {
                j["GitHub Workflow SHA"] = json!(val);
            }
        } else if ext.oid == oid!(1.3.6 .1 .4 .1 .57264 .1 .4) {
            if let Ok(val) = std::str::from_utf8(ext.value) {
                j["GitHub Workflow Name"] = json!(val);
            }
        } else if ext.oid == oid!(1.3.6 .1 .4 .1 .57264 .1 .5) {
            if let Ok(val) = std::str::from_utf8(ext.value) {
                j["GitHub Workflow Repository"] = json!(val);
            }
        } else if ext.oid == oid!(1.3.6 .1 .4 .1 .57264 .1 .6) {
            if let Ok(val) = std::str::from_utf8(ext.value) {
                j["GitHub Workflow Ref"] = json!(val);
            }
        } else {
            // println!("Unparsed: {}", ext.oid);
        }
    }

    println!("{j}");
    Ok(())
}

fn parse_entry(entry: &Value) -> Result<(), Box<dyn Error>> {
    // Each entry is a dictionary with a single parent key (the cert hash)
    let entry = entry
        .as_object()
        .ok_or("Bad Entry, should be an object")?
        .values()
        .next()
        .ok_or("Bad Entry, should have a single key")?;

    let log_index = entry["logIndex"].as_u64().ok_or("Bad Log Index")?;

    let body = String::from_utf8(base64::decode(
        entry["body"].as_str().ok_or("Missing Body")?,
    )?)?;
    let body: Value = serde_json::from_str(&body)?;

    let hash_type = body
        .pointer("/spec/data/hash/algorithm")
        .ok_or("Couldn't get hash type")?
        .as_str()
        .ok_or("content parse hash type")?;
    let hash_value = body
        .pointer("/spec/data/hash/value")
        .ok_or("Couldn't get hash type")?
        .as_str()
        .ok_or("content parse hash type")?;
    let hash = format!("{hash_type}:{hash_value}");

    let certb64 = body
        .pointer("/spec/signature/publicKey/content")
        .ok_or("Couldn't find pubkey content")?
        .as_str()
        .ok_or("content content not String")?;
    let data_b64 = base64::decode(certb64)?;

    match parse_x509_pem(&data_b64) {
        Ok((_, pem)) => {
            // Ignore Public Keys, only look at certs
            if pem.label == "CERTIFICATE" {
                let (_, cert) = parse_x509_certificate(&pem.contents)?;
                log_data(log_index, &hash, &cert)?;
            }
        }
        Err(e) => {
            eprintln!("PEM parsing failed: {:?}", e);
        }
    }

    Ok(())
}

fn get_entries(client: &Client, range: &Vec<u64>) -> Result<(), Box<dyn Error>> {
    let data = json!({ "logIndexes": range });
    let resp: Value = client
        .post("https://rekor.sigstore.dev/api/v1/log/entries/retrieve")
        .json(&data)
        .send()?
        .json()?;

    for entry in resp.as_array().ok_or("Entries response wasn't an array")? {
        if let Err(e) = parse_entry(entry) {
            eprintln!("Error Parsing Entry: {e}");
        }
    }

    Ok(())
}

fn get_latest_id() -> Result<u64, Box<dyn Error>> {
    let resp: Value = reqwest::blocking::get("https://rekor.sigstore.dev/api/v1/log")?.json()?;

    let mut size = resp["treeSize"]
        .as_u64()
        .ok_or("Response missing treeSize")?;

    for shard in resp["inactiveShards"]
        .as_array()
        .ok_or("Bad inactiveShards")?
    {
        size += shard["treeSize"].as_u64().ok_or("Bad inactiveShards")?;
    }

    Ok(size)
}

fn main() -> Result<(), Box<dyn Error>> {
    // Parse args
    let args = Args::parse();

    // Do stuff
    eprintln!("[ ] Start");
    // Get one before the latest id
    let mut last_size = get_latest_id()?.saturating_sub(1);
    let client = reqwest::blocking::Client::new();
    loop {
        let new_size = get_latest_id()?;
        if new_size == last_size {
            continue;
        }

        let range: Vec<u64> = (last_size..new_size).collect();
        eprintln!(
            "[ ] Getting: {} -> {} ({})",
            range[0],
            range[range.len() - 1],
            range.len()
        );

        if let Err(e) = get_entries(&client, &range) {
            eprintln!("Error Getting Range: {e}");
        }

        // Sleep to acrue a range of IDs
        thread::sleep(time::Duration::from_secs(args.interval));
        last_size = new_size;
    }
    // Ok(())
}
