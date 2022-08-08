use age::secrecy::Secret;
use reqwest;
use rpassword;
use tokio::task;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicIsize;
use std::sync::atomic::Ordering;
use serde_json::Value;
use std::fs::File;
use std::io;
use std::fs;
use std::io::Read;
use std::io::Write;

#[tokio::main]
async fn main() {
    if Path::new("temp/").exists() {
        fs::remove_dir_all("temp/").unwrap();
    }
    
    print!("Do you want to\n(d)ownload\n(r)ename & decrypt\n");
    io::stdout().flush().unwrap();
    let mut startbuf = String::new();
    io::stdin().read_line(&mut startbuf).expect("Failed to read from stdin");
    let execute = startbuf.trim().to_string();
    if execute != "d" && execute != "r" {
        println!("Invalid answer, quitting...");
    }

    if execute == "d" {
        download().await;
    }
    else if execute == "r" {
        rename();
    }
}

async fn download() {
    print!("Please paste your Malshare API key: ");
    io::stdout().flush().unwrap();
    let malshareapi = rpassword::read_password().unwrap();

    let mut map = HashMap::new();
    map.insert("query", "get_file_type");
    map.insert("file_type", "exe");
    map.insert("limit", "1000");

    println!("Getting data from Malshare...");

    let msres = reqwest::Client::new()
        .get(format!("https://malshare.com/api.php?api_key={}&action=getlist", malshareapi))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let msjson: Value = match serde_json::from_str(&msres) {
        Ok(json) => json,
        Err(_) => {
            println!("Failed to get data from Malshare: Invalid api key or there is no quota remaining");
            print!("Do you want to\n(q)uit\n(c)ontinue\n");
            io::stdout().flush().unwrap();
            let mut failbuf = String::new();
            io::stdin().read_line(&mut failbuf).expect("Failed to read from stdin");
            let answer = failbuf.trim().to_string();
            if answer != "q" && answer != "c" {
                println!("Invalid answer, quitting...");
            }
            if answer == "q" {
                return;
            }
            serde_json::from_str("[{}]").unwrap()
        }
    };

    println!("Done");

    println!("Getting data from Malwarebazaar...");

    let mbres = reqwest::Client::new()
        .post("https://mb-api.abuse.ch/api/v1/")
        .form(&map)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    
    println!("Done");
        
    let mbjson: Value = serde_json::from_str(&mbres).unwrap();

    let mbdata = mbjson.get("data").unwrap().as_array().unwrap().clone();
    let msdata = msjson.as_array().unwrap().clone();

    if Path::new("samples/").exists() {
        let dirstat = fs::read_dir("samples/").unwrap();
        if dirstat.count() != 0 {
            loop {
                print!("The samples directory already exists, do you want to\n(d)elete\n(b)ackup\n");
                io::stdout().flush().unwrap();
                let mut samplebuf = String::new();
                io::stdin().read_line(&mut samplebuf).expect("Failed to read from stdin");
                let sampleanswer = samplebuf.trim().to_string();
                if sampleanswer == "d" {
                    println!("Deleting the samples directory...");
                    fs::remove_dir_all("samples/").unwrap();
                    println!("Done");
                    break;
                }
                else if sampleanswer == "b" {
                    fs::create_dir_all("samples-backup/").unwrap();
                    let backupfiles = fs::read_dir("samples/").unwrap();
                    for backupfile in backupfiles {
                        let fullfile;
                        if backupfile.as_ref().unwrap().path().extension().is_none() {
                            fullfile = format!("{}", backupfile.as_ref().unwrap().path().file_name().unwrap().to_str().unwrap());
                        }
                        else {
                            fullfile = format!("{}.{}", backupfile.as_ref().unwrap().path().file_name().unwrap().to_str().unwrap(), backupfile.as_ref().unwrap().path().extension().unwrap().to_str().unwrap());
                        }
                        fs::copy(backupfile.as_ref().unwrap().path().display().to_string(), format!("samples-backup/{}", fullfile)).unwrap();
                        fs::remove_file(backupfile.as_ref().unwrap().path().display().to_string()).unwrap();
                    }
                    fs::remove_dir_all("samples/").unwrap();
                    break;
                }
                else {
                    println!("Invalid option");
                }
            }
        }  
    }

    fs::create_dir_all("temp/").unwrap();
    fs::create_dir_all("samples/").unwrap(); 

    let count = Arc::new(AtomicIsize::new((mbdata.len() + msdata.len()).try_into().unwrap()));
    let count_clone = count.clone();

    let downloaded = Arc::new(AtomicIsize::new(1));
    let downloaded_clone = downloaded.clone();

    let mut handles = vec![];

    handles.push(task::spawn(async move {
        for i in 0..mbdata.len() {
            let hash = &mbdata[i]["sha256_hash"];
    
            let mut map = HashMap::new();
            map.insert("query", "get_file");
            map.insert("sha256_hash", hash.as_str().unwrap());
    
            let res = reqwest::Client::new()
                .post("https://mb-api.abuse.ch/api/v1/")
                .form(&map)
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap();
    
            let downloadedcopy = downloaded.load(Ordering::SeqCst).clone();
            let mut out = File::create(format!("temp/sample{}.zip", downloadedcopy)).unwrap();
    
            let mut bytes : &[u8] = &res;
            io::copy(&mut bytes, &mut out).unwrap();
    
            let zip = File::open(format!("temp/sample{}.zip", downloadedcopy)).unwrap();
    
            let mut archive = match zip::ZipArchive::new(zip) {
                Ok(archive) => archive,
                Err(_e) => {
                    println!("Can't load zip file, skipping file");
                    count.fetch_add(-1, Ordering::SeqCst);
                    continue;
                }
            };   
    
            let mut file = archive
                .by_index_decrypt(0, "infected".as_bytes())
                .unwrap()
                .unwrap();
    
            let mut data = Vec::new();
            file.read_to_end(&mut data).unwrap();
            
            let mut fileout = File::create(format!("samples/sample{}", downloaded.load(Ordering::SeqCst))).unwrap();

            let databytes : &[u8] = &data;
            let encryptor = age::Encryptor::with_user_passphrase(Secret::new("maliciousfileutil".to_owned()));
            let mut encrypted = vec![];
            let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
            writer.write_all(databytes).unwrap();
            writer.finish().unwrap();
            let mut samplebytes : &[u8] = &encrypted;

            io::copy(&mut samplebytes, &mut fileout).unwrap();
    
            println!("Downloaded file {}/{} from Malwarebazaar", downloaded.load(Ordering::SeqCst), count.load(Ordering::SeqCst));
            downloaded.fetch_add(1, Ordering::SeqCst);
        }
    }));

    handles.push(task::spawn(async move {
        for i in 0..msdata.len() {
            if msdata[i]["sha256"].as_str().is_none() {
                return;
            }
            let hash = &msdata[i]["sha256"].as_str().unwrap();

            let res = reqwest::Client::new()
                .get(format!("https://malshare.com/api.php?api_key={}&action=getfile&hash={}", malshareapi, hash))
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap();

            let mut out = File::create(format!("samples/sample{}", downloaded_clone.load(Ordering::SeqCst))).unwrap();

            let resbytes : &[u8] = &res;
            let encryptor = age::Encryptor::with_user_passphrase(Secret::new("maliciousfileutil".to_owned()));
            let mut encrypted = vec![];
            let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
            writer.write_all(resbytes).unwrap();
            writer.finish().unwrap();
            let mut bytes : &[u8] = &encrypted;

            io::copy(&mut bytes, &mut out).unwrap();

            println!("Downloaded file {}/{} from Malshare", downloaded_clone.load(Ordering::SeqCst), count_clone.load(Ordering::SeqCst));
            downloaded_clone.fetch_add(1, Ordering::SeqCst);
        }
    }));

    futures::future::join_all(handles).await;
    fs::remove_dir_all("temp/").unwrap();
}

fn rename() {
    if !Path::new("samples/").exists() {
        println!("Cannot find the samples directory, quitting...");
        return;
    }

    let samples = fs::read_dir("samples/").unwrap();
    for sample in samples {
        if !sample.as_ref().unwrap().path().extension().is_none() {
            println!("{} is already renamed and decrypted", sample.unwrap().path().file_name().unwrap().to_str().unwrap());
            continue;
        }
        let data = fs::read(sample.as_ref().unwrap().path()).unwrap();
        
        let decryptor = match age::Decryptor::new(&data[..]) {
            Ok(age::Decryptor::Passphrase(d)) => d,
            _ => {
                println!("Can't decrypt {}, skipping file", sample.unwrap().path().file_name().unwrap().to_str().unwrap());
                continue;
            }
        };

        let mut decrypted = vec![];
        let mut reader = decryptor.decrypt(&Secret::new("maliciousfileutil".to_owned()), None).unwrap();
        let _ = match reader.read_to_end(&mut decrypted) {
            Ok(o) => o,
            Err(_) => {
                println!("Can't decrypt {}, skipping file", sample.unwrap().path().file_name().unwrap().to_str().unwrap());
                continue;
            }
        };
        
        let mut out = fs::OpenOptions::new().write(true).open(sample.as_ref().unwrap().path().display().to_string()).unwrap();

        let mut bytes : &[u8] = &decrypted;

        io::copy(&mut bytes, &mut out).unwrap();

        let _ = match fs::rename(sample.as_ref().unwrap().path().display().to_string(), format!("{}.exe", sample.as_ref().unwrap().path().display())) {
            Ok(res) => res,
            Err(_) => {
                println!("Cannot rename {}, skipping file", sample.unwrap().path().file_name().unwrap().to_str().unwrap());
                continue;
            }
        };
        println!("Renamed {}", sample.unwrap().path().file_name().unwrap().to_str().unwrap())
    }
}