use aes_gcm_siv::Aes256GcmSiv;
use aes_gcm_siv::KeyInit;
use aes_gcm_siv::Nonce;
use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::aead::generic_array::GenericArray;
use reqwest;
use reqwest::StatusCode;
use rpassword;
use tokio::task;
use std::collections::HashMap;
use std::path::Path;
use std::process;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
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

    loop {
        print!("1. Download\n2. Backup\n3. Restore\n4. Run\nType the number of the action you want to run: ");
        io::stdout().flush().unwrap();
        let mut startbuf = String::new();
        io::stdin().read_line(&mut startbuf).expect("Failed to read from stdin");
        let execute = startbuf.trim().to_string();
        if execute != "1" && execute != "2" && execute != "3" && execute != "4" {
            println!("Invalid option\n");
            continue;
        }

        if execute == "1" {
            download().await;
            return;
        }
        else if execute == "2" {
            backup();
            return;
        }
        else if execute == "3" {
            restore();
            return;
        }
        else if execute == "4" {
            run();
            return
        }
    }

}

async fn download() {
    let mut map = HashMap::new();
    map.insert("query", "get_file_type");
    map.insert("file_type", "exe");
    map.insert("limit", "1000");

    print!("Please paste your Malshare API key: ");
    io::stdout().flush().unwrap();
    let malshareapi = rpassword::read_password().unwrap();

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
            println!("\nFailed to get data from Malshare: Invalid API key or there is no quota remaining");
            loop {
                print!("Do you want to\n1. Continue\n2. Quit\nType the number of the action you want to run: ");
                io::stdout().flush().unwrap();
                let mut failbuf = String::new();
                io::stdin().read_line(&mut failbuf).expect("Failed to read from stdin");
                let answer = failbuf.trim().to_string();
                if answer != "1" && answer != "2" {
                    println!("Invalid option\n");
                    continue;
                }
                if answer == "2" {
                    return;
                }
                break;
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
            println!("\nThe samples directory already exists");
            loop {
                print!("Do you want to\n1. Delete\n2. Backup\nType the number of the action you want to run: ");
                io::stdout().flush().unwrap();
                let mut samplebuf = String::new();
                io::stdin().read_line(&mut samplebuf).expect("Failed to read from stdin");
                let sampleanswer = samplebuf.trim().to_string();
                if sampleanswer == "1" {
                    println!("Deleting the samples directory...");
                    fs::remove_dir_all("samples/").unwrap();
                    println!("Done");
                    break;
                }
                else if sampleanswer == "2" {
                    if Path::new("samples-backup/").exists() {
                        let backupstat = fs::read_dir("samples-backup/").unwrap();
                        if backupstat.count() != 0 {
                            println!("\nThe backup directory already exists");
                            loop {
                                print!("Do you want to\n1. Delete\n2. Quit\nType the number of the action you want to run: ");
                                io::stdout().flush().unwrap();
                                let mut backupbuf = String::new();
                                io::stdin().read_line(&mut backupbuf).expect("Failed to read from stdin");
                                let backupanswer = backupbuf.trim().to_string();
                                if backupanswer != "1" && backupanswer != "2" {
                                    println!("Invalid option\n");
                                }
                                if backupanswer == "1" {
                                    println!("Deleting the backup directory...");
                                    fs::remove_dir_all("samples-backup/").unwrap();
                                    println!("Done");
                                    break;
                                }
                                if backupanswer == "2" {
                                    return;
                                }
                            }
                        }
                    }
                    println!("Backing up samples...");
                    fs::create_dir_all("samples-backup/").unwrap();
                    let backupfiles = fs::read_dir("samples/").unwrap();
                    for backupfile in backupfiles {
                        let fullfile;
                        if backupfile.as_ref().unwrap().path().extension().is_none() {
                            fullfile = format!("{}", backupfile.as_ref().unwrap().path().file_name().unwrap().to_str().unwrap());
                        }
                        else {
                            fullfile = format!("{}", backupfile.as_ref().unwrap().path().file_name().unwrap().to_str().unwrap());
                        }
                        fs::copy(backupfile.as_ref().unwrap().path().display().to_string(), format!("samples-backup/{}", fullfile)).unwrap();
                        fs::remove_file(backupfile.as_ref().unwrap().path().display().to_string()).unwrap();
                    }
                    fs::remove_dir_all("samples/").unwrap();
                    println!("Done");
                    break;
                }
                else {
                    println!("Invalid option\n");
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

    let pause = Arc::new(AtomicBool::new(false));
    let pause_clone = pause.clone();

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
    
            let mut bytes: &[u8] = &res;
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
            
            let mut fileout = File::create(format!("samples/sample{}.exe", downloaded.load(Ordering::SeqCst))).unwrap();

            let mut databytes: &[u8] = &data;

            io::copy(&mut databytes, &mut fileout).unwrap();
    
            if pause.load(Ordering::SeqCst) == true {
                loop {
                    if pause.load(Ordering::SeqCst) == false {
                        break;
                    }
                }
            }

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
                .unwrap();
            
            if res.status() == StatusCode::TOO_MANY_REQUESTS {
                pause_clone.store(true, Ordering::SeqCst);
                println!("\nError while trying to get a file from Malshare, most likely there is no more quota remaining");
                loop {
                    print!("Do you want to\n1. Continue without Malshare\n2. Quit\nType the number of the action you want to run: ");
                    io::stdout().flush().unwrap();
                    let mut errbuf = String::new();
                    io::stdin().read_line(&mut errbuf).expect("Failed to read from stdin");
                    let erranswer = errbuf.trim().to_string();
                    if erranswer != "1" && erranswer != "2" {
                        println!("Invalid option\n");
                    }
                    if erranswer == "1" {
                        count_clone.fetch_sub(msdata.len().try_into().unwrap(), Ordering::SeqCst);
                        pause_clone.store(false, Ordering::SeqCst);
                        return;
                    }
                    if erranswer == "2" {
                        process::exit(0);
                    }
                }
            }

            let mut resbytes: &[u8] = &res.bytes().await.unwrap();
        
            let mut out = File::create(format!("samples/sample{}.exe", downloaded_clone.load(Ordering::SeqCst))).unwrap();

            io::copy(&mut resbytes, &mut out).unwrap();

            println!("Downloaded file {}/{} from Malshare", downloaded_clone.load(Ordering::SeqCst), count_clone.load(Ordering::SeqCst));
            downloaded_clone.fetch_add(1, Ordering::SeqCst);
        }
    }));

    futures::future::join_all(handles).await;
    fs::remove_dir_all("temp/").unwrap();
}

fn backup() {
    if !Path::new("samples/").exists() {
        println!("Cannot find the samples directory, quitting...");
        return;
    }

    let samples = fs::read_dir("samples/").unwrap();
    for sample in samples {

        let data: &[u8] = &match fs::read(sample.as_ref().unwrap().path()) {
            Ok(d) => d,
            Err(_) => {
                println!("Cannot read {}, skipping file", sample.as_ref().unwrap().path().file_stem().unwrap().to_str().unwrap());
                continue;
            }
        };

        let key = GenericArray::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]);
        let cipher = Aes256GcmSiv::new(&key);
        let nonce = Nonce::from_slice(b"malwarefiles");
    
        let encrypted = cipher.encrypt(nonce, data).unwrap();
    
        let mut bytes: &[u8] = &encrypted;

        let mut out = fs::OpenOptions::new().write(true).open(sample.as_ref().unwrap().path()).unwrap();
    
        io::copy(&mut bytes, &mut out).unwrap();

        match fs::rename(sample.as_ref().unwrap().path().display().to_string(), format!("{}/{}.backup", sample.as_ref().unwrap().path().parent().unwrap().to_str().unwrap(), sample.as_ref().unwrap().path().file_stem().unwrap().to_str().unwrap())) {
            Ok(()) => (),
            Err(_) => {
                println!("Cannot rename {}, skipping file renaming", sample.as_ref().unwrap().path().file_stem().unwrap().to_str().unwrap());
                ()
            }
        };

        println!("Backupped {}", sample.as_ref().unwrap().path().file_stem().unwrap().to_str().unwrap());
    }

}

fn restore() {
    if !Path::new("samples/").exists() {
        println!("Cannot find the samples directory, quitting...");
        return;
    }

    let samples = fs::read_dir("samples/").unwrap();
    for sample in samples {
        if sample.as_ref().unwrap().path().extension().unwrap().to_str().unwrap() != "backup" {
            println!("{} is already restored", sample.as_ref().unwrap().path().file_stem().unwrap().to_str().unwrap());
            continue;
        }

        match fs::rename(sample.as_ref().unwrap().path().display().to_string(), format!("{}/{}.exe", sample.as_ref().unwrap().path().parent().unwrap().to_str().unwrap(), sample.as_ref().unwrap().path().file_stem().unwrap().to_str().unwrap())) {
            Ok(()) => (),
            Err(_) => {
                println!("Cannot rename {}, skipping file renaming", sample.as_ref().unwrap().path().file_stem().unwrap().to_str().unwrap());
                ()
            }
        };

        let data: &[u8] = &fs::read(format!("{}/{}.exe", sample.as_ref().unwrap().path().parent().unwrap().to_str().unwrap(), sample.as_ref().unwrap().path().file_stem().unwrap().to_str().unwrap())).unwrap();

        let key = GenericArray::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]);
        let cipher = Aes256GcmSiv::new(&key);
        let nonce = Nonce::from_slice(b"malwarefiles");
    
        let decrypted = match cipher.decrypt(nonce, data) {
            Ok(d) => d,
            Err(_) => {
                println!("Cannot decrypt {}, skipping file", sample.as_ref().unwrap().path().file_stem().unwrap().to_str().unwrap());
                continue;
            }
        };
        
        let mut out = fs::OpenOptions::new().write(true).open(format!("{}/{}.exe", sample.as_ref().unwrap().path().parent().unwrap().to_str().unwrap(), sample.as_ref().unwrap().path().file_stem().unwrap().to_str().unwrap())).unwrap();

        let mut bytes: &[u8] = &decrypted;

        io::copy(&mut bytes, &mut out).unwrap();

        println!("Restored {}", sample.as_ref().unwrap().path().file_stem().unwrap().to_str().unwrap())
    }
}

fn run() {
    let samples = fs::read_dir("samples/").unwrap();
    for sample in samples {
        if sample.as_ref().unwrap().path().extension().unwrap().to_str().unwrap() == "backup" {
            println!("{} seems to be a backup, try restoring the files first", sample.as_ref().unwrap().path().file_stem().unwrap().to_str().unwrap());
            continue;
        }

        match Command::new(sample.as_ref().unwrap().path().display().to_string()).spawn() {
            Ok(c) => c,
            Err(e) => {
                println!("Something went wrong trying to run {}\nError: {}\n", sample.as_ref().unwrap().path().file_name().unwrap().to_str().unwrap(), e);
                continue;
            }
        };
    }
}