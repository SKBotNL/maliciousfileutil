// Copyright 2022 SKBotNL
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::io::{stdin, stdout};
use aes_gcm_siv::aead::generic_array::GenericArray;
use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::Aes256GcmSiv;
use aes_gcm_siv::KeyInit;
use aes_gcm_siv::Nonce;
use console::Style;
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use nipper::Document;
use reqwest;
use reqwest::header::SET_COOKIE;
use reqwest::StatusCode;
use reqwest::Url;
use rpassword;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::path::Path;
use std::process;
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicIsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::task;

#[tokio::main]
async fn main() {
    if Path::new("temp/").exists() {
        fs::remove_dir_all("temp/").unwrap();
    }

    loop {
        print!("1. Download\n2. Backup\n3. Restore\n4. Run\nType the number of the action you want to run: ");
        stdout().flush().unwrap();
        let mut startbuf = String::new();
        stdin()
            .read_line(&mut startbuf)
            .expect("Failed to read from stdin");
        let execute = startbuf.trim().to_string();
        if execute != "1" && execute != "2" && execute != "3" && execute != "4" {
            println!("Invalid option\n");
            continue;
        }

        if execute == "1" {
            download().await;
            return;
        } else if execute == "2" {
            backup().await;
            return;
        } else if execute == "3" {
            restore().await;
            return;
        } else if execute == "4" {
            run();
            return;
        }
    }
}

async fn download() {
    let mut enabledsources = vec![];

    loop {
        print!("\nChoose the malware sources you want to use\n1. Malwarebazaar\n2. Malshare\n3. VX Vault\nType the numbers of the sources you want to use seperated by spaces: ");
        stdout().flush().unwrap();
        let mut choicebuf = String::new();
        stdin()
            .read_line(&mut choicebuf)
            .expect("Failed to read from stdin");

        let choicesplit = choicebuf.split_whitespace();

        let mut quit = true;

        for choice in choicesplit {
            match choice {
                "1" => enabledsources.push("malwarebazaar"),
                "2" => enabledsources.push("malshare"),
                "3" => enabledsources.push("vxvault"),
                _ => quit = false,
            }
        }

        if enabledsources.is_empty() {
            println!("\nPlease enter atleast one source\n");
            continue;
        }

        if quit {
            break;
        }
        println!("\nYou have entered one or more invalid number(s)\n")
    }

    if enabledsources.contains(&"vxvault") {
        println!("\nPlease enable your VPN before continuing\nPress enter to continue...");
        stdout().flush().unwrap();
        let mut void = String::new();
        stdin()
            .read_line(&mut void)
            .expect("Failed to read from stdin");

        println!("Waiting for an internet connection...\n");
        loop {
            if let Ok(_) = TcpStream::connect("1.1.1.1:80") {
                break;
            } else {
                continue;
            }
        }
    }

    let mut msdata = vec![];
    let mut malshareapi = String::new();

    if enabledsources.contains(&"malshare") {
        print!("Please paste your Malshare API key: ");
        stdout().flush().unwrap();
        malshareapi = rpassword::read_password().unwrap();

        println!("\nGetting data from Malshare...");

        let msres = reqwest::Client::new()
            .get(format!(
                "https://malshare.com/api.php?api_key={}&action=getlist",
                malshareapi
            ))
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
                    stdout().flush().unwrap();
                    let mut failbuf = String::new();
                    stdin()
                        .read_line(&mut failbuf)
                        .expect("Failed to read from stdin");
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
                serde_json::from_str("[]").unwrap()
            }
        };

        msdata = msjson.as_array().unwrap().clone();

        println!("Done");
    }

    let mut mblist: Vec<String> = Vec::new();

    if enabledsources.contains(&"malwarebazaar") {
        println!("Getting data from Malwarebazaar...");

        let mut map = HashMap::new();
        map.insert("query", "get_file_type");
        map.insert("file_type", "exe");
        map.insert("limit", "1000");

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

        println!("Filtering data from Malwarebazaar...");

        let mbjson: Value = serde_json::from_str(&mbres).unwrap();
        let mbdata = mbjson.get("data").unwrap().as_array().unwrap().clone();

        let mut signatures: Vec<String> = Vec::new();

        for i in 0..mbdata.len() {
            let hash = mbdata[i]["sha256_hash"].to_string().replace("\"", "");
            let signature = mbdata[i]["signature"].to_string();
            if signatures.contains(&signature) {
                continue;
            }
            signatures.push(signature);
            mblist.push(hash);
        }

        println!("Done");
    }

    let mut vxurls = vec![];

    if enabledsources.contains(&"vxvault") {
        let vxcount;
        loop {
            print!("How many samples do you want to query from VX Vault? (I don't recommend more than 1000): ");
            stdout().flush().unwrap();
            let mut vxbuf = String::new();
            stdin()
                .read_line(&mut vxbuf)
                .expect("Failed to read from stdin");

            let vxstr: String = vxbuf.split_whitespace().collect();

            vxcount = match vxstr.parse::<i32>() {
                Ok(i) => i,
                Err(_) => {
                    println!("Please enter a valid number");
                    continue;
                }
            };

            break;
        }

        println!("Getting data from VX Vault...");

        // Using HTTP because VX Vault's certificate isn't "trusted"
        let mut map = HashMap::new();
        map.insert("login", "infected");
        map.insert("password", "infected");

        let vxcookie = reqwest::Client::new()
            .post("http://vxvault.net/login.php")
            .form(&map)
            .send()
            .await
            .unwrap();

        let cookie = vxcookie
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();

        // Using HTTP because VX Vault's certificate isn't trusted
        let vxres = reqwest::Client::new()
            .get(format!("http://vxvault.net/ViriList.php?s=0&m={}", vxcount))
            .header("Cookie", cookie)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();

        let document = Document::from(&vxres);

        document.select("tr").iter().skip(1).for_each(|athing| {
            let url = athing
                .children()
                .get(1)
                .unwrap()
                .children()
                .get(2)
                .unwrap()
                .text()
                .to_string();

            if url.ends_with("exe") {
                vxurls.push(format!("http://{}", url));
            }
        });

        println!("Done");
    }

    if Path::new("samples/").exists() {
        let dirstat = fs::read_dir("samples/").unwrap();
        if dirstat.count() != 0 {
            println!("\nThe samples directory already exists");
            loop {
                print!("Do you want to\n1. Delete\n2. Backup\nType the number of the action you want to run: ");
                stdout().flush().unwrap();
                let mut samplebuf = String::new();
                stdin()
                    .read_line(&mut samplebuf)
                    .expect("Failed to read from stdin");
                let sampleanswer = samplebuf.trim().to_string();
                if sampleanswer == "1" {
                    println!("Deleting the samples directory...");
                    fs::remove_dir_all("samples/").unwrap();
                    println!("Done");
                    break;
                } else if sampleanswer == "2" {
                    if Path::new("samples-backup/").exists() {
                        let backupstat = fs::read_dir("samples-backup/").unwrap();
                        if backupstat.count() != 0 {
                            println!("\nThe backup directory already exists");
                            loop {
                                print!("Do you want to\n1. Delete\n2. Quit\nType the number of the action you want to run: ");
                                stdout().flush().unwrap();
                                let mut backupbuf = String::new();
                                stdin()
                                    .read_line(&mut backupbuf)
                                    .expect("Failed to read from stdin");
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
                            fullfile = format!(
                                "{}",
                                backupfile
                                    .as_ref()
                                    .unwrap()
                                    .path()
                                    .file_name()
                                    .unwrap()
                                    .to_str()
                                    .unwrap()
                            );
                        } else {
                            fullfile = format!(
                                "{}",
                                backupfile
                                    .as_ref()
                                    .unwrap()
                                    .path()
                                    .file_name()
                                    .unwrap()
                                    .to_str()
                                    .unwrap()
                            );
                        }
                        fs::copy(
                            backupfile.as_ref().unwrap().path().display().to_string(),
                            format!("samples-backup/{}", fullfile),
                        )
                        .unwrap();
                        fs::remove_file(backupfile.as_ref().unwrap().path().display().to_string())
                            .unwrap();
                    }
                    fs::remove_dir_all("samples/").unwrap();
                    println!("Done");
                    break;
                } else {
                    println!("Invalid option\n");
                }
            }
        }
    }

    fs::create_dir_all("temp/").unwrap();
    fs::create_dir_all("samples/").unwrap();

    let downloaded = Arc::new(AtomicIsize::new(1));
    let downloaded_ms = downloaded.clone();
    let downloaded_vx = downloaded.clone();

    let pause = Arc::new(AtomicBool::new(false));
    let pause_ms = pause.clone();
    let pause_vx = pause.clone();

    let mut count = 0;

    for source in &enabledsources {
        match source {
            &"malwarebazaar" => count += mblist.len(),
            &"malshare" => count += msdata.len(),
            &"vxvault" => count += vxurls.len(),
            _ => {}
        }
    }

    let pb = ProgressBar::new(count as u64);
    pb.set_style(
        ProgressStyle::with_template("{prefix.cyan.bold} [{bar:57}] {pos}/{len}")
            .unwrap()
            .progress_chars("=> "),
    );
    pb.set_prefix("Downloading");

    let pb_ms = pb.clone();
    let pb_vx = pb.clone();

    let mut handles = vec![];

    if enabledsources.contains(&"malwarebazaar") {
        handles.push(task::spawn(async move {
            let red_bold = Style::new().red().bold();
            let green_bold = Style::new().green().bold();

            for i in 0..mblist.len() {
                let hash = &mblist[i];

                let mut map = HashMap::new();
                map.insert("query", "get_file");
                map.insert("sha256_hash", hash);

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
                        pb.println(format!(
                            "{} can't load zip file, skipping file",
                            red_bold.apply_to("Error")
                        ));
                        pb.set_length(pb.length().unwrap() - 1);
                        continue;
                    }
                };

                let mut file = archive
                    .by_index_decrypt(0, "infected".as_bytes())
                    .unwrap()
                    .unwrap();

                let mut data = Vec::new();
                file.read_to_end(&mut data).unwrap();

                let mut fileout = File::create(format!(
                    "samples/sample{}.exe",
                    downloaded.load(Ordering::SeqCst)
                ))
                .unwrap();

                let mut databytes: &[u8] = &data;

                io::copy(&mut databytes, &mut fileout).unwrap();

                if pause.load(Ordering::SeqCst) == true {
                    loop {
                        if pause.load(Ordering::SeqCst) == false {
                            break;
                        }
                    }
                }

                pb.println(format!(
                    "{} sample{} from Malwarebazaar",
                    green_bold.apply_to("Downloaded"),
                    downloaded.load(Ordering::SeqCst)
                ));
                pb.inc(1);
                downloaded.fetch_add(1, Ordering::SeqCst);
            }
            if Path::new("temp/").exists() {
                fs::remove_dir_all("temp/").unwrap();
            }
            pb.println(format!(
                "{} all samples from Malwarebazaar have been downloaded",
                green_bold.apply_to("Done")
            ));
        }));
    }

    if enabledsources.contains(&"malshare") {
        handles.push(task::spawn(async move {
            let green_bold = Style::new().green().bold();

            let mut retry = false;

            let mut localapi = malshareapi.to_string();
            for i in 0..msdata.len() {
                if msdata[i]["sha256"].as_str().is_none() {
                    return;
                }
                let hash = &msdata[i]["sha256"].as_str().unwrap();

                let mut res = reqwest::Client::new()
                    .get(format!("https://malshare.com/api.php?api_key={}&action=getfile&hash={}", localapi, hash))
                    .send()
                    .await
                    .unwrap();

                if res.status() == StatusCode::TOO_MANY_REQUESTS {
                    pause_ms.store(true, Ordering::SeqCst);
                    println!("\nError while trying to get a file from Malshare, most likely there is no more quota remaining");
                    loop {
                        print!("Do you want to\n1. Continue without Malshare\n2. Change API key\n3. Quit\nType the number of the action you want to run: ");
                        stdout().flush().unwrap();
                        let mut errbuf = String::new();
                        stdin().read_line(&mut errbuf).expect("Failed to read from stdin");
                        let erranswer = errbuf.trim().to_string();
                        if erranswer != "1" && erranswer != "2" && erranswer != "3" {
                            println!("Invalid option\n");
                        }
                        if erranswer == "1" {
                            pb_ms.set_length(pb_ms.length().unwrap() - (msdata.len() as u64));
                            pause_ms.store(false, Ordering::SeqCst);
                            return;
                        }
                        if erranswer == "2" {
                            loop {
                                print!("\nPlease paste your Malshare API key: ");
                                stdout().flush().unwrap();
                                let apianswer = rpassword::read_password().unwrap();

                                let checkres = reqwest::Client::new()
                                    .get(format!("https://malshare.com/api.php?api_key={}&action=getlimit", apianswer))
                                    .send()
                                    .await
                                    .unwrap();

                                if checkres.status() == StatusCode::UNAUTHORIZED {
                                    println!("Invalid API key");
                                    continue;
                                }

                                let checktext = checkres.text().await.unwrap();
                                let checkjson: Value = serde_json::from_str(&checktext).unwrap();
                                let remaining = checkjson.get("REMAINING").unwrap();
                                if remaining == "0" {
                                    println!("No quota remaining")
                                }

                                localapi = apianswer;
                                break;
                            }
                            pause_ms.store(false, Ordering::SeqCst);
                            retry = true;
                            break;
                        }
                        if erranswer == "3" {
                            process::exit(0);
                        }
                    }
                    pb_ms.tick();
                }

                if retry {
                    res = reqwest::Client::new()
                        .get(format!("https://malshare.com/api.php?api_key={}&action=getfile&hash={}", localapi, hash))
                        .send()
                        .await
                        .unwrap();

                    retry = false;
                }

                let mut resbytes: &[u8] = &res.bytes().await.unwrap();

                let mut out = File::create(format!("samples/sample{}.exe", downloaded_ms.load(Ordering::SeqCst))).unwrap();

                io::copy(&mut resbytes, &mut out).unwrap();

                pb_ms.println(format!("{} sample{} from Malshare", green_bold.apply_to("Downloaded"), downloaded_ms.load(Ordering::SeqCst)));
                pb_ms.inc(1);
                downloaded_ms.fetch_add(1, Ordering::SeqCst);
            }

            pb_ms.println(format!("{} all samples from Malshare have been downloaded", green_bold.apply_to("Done")));
        }));
    }

    if enabledsources.contains(&"vxvault") {
        handles.push(task::spawn(async move {
            let mut blacklist = vec![];
            let green_bold = Style::new().green().bold();

            for url in vxurls {
                let host = Url::parse(&url).unwrap().host().unwrap().to_string();
                if blacklist.contains(&host) {
                    pb_vx.set_length(pb_vx.length().unwrap() - 1);
                    continue;
                }

                let result = reqwest::Client::new()
                    .get(url)
                    .timeout(Duration::from_secs(15))
                    .send()
                    .await;

                let res = match result {
                    Ok(res) => res,
                    Err(_) => {
                        blacklist.push(host);
                        pb_vx.set_length(pb_vx.length().unwrap() - 1);
                        continue;
                    }
                };

                if StatusCode::is_server_error(&res.status())
                    || StatusCode::is_client_error(&res.status())
                {
                    continue;
                }

                let mut resbytes: &[u8] = &res.bytes().await.unwrap();

                let mut out = File::create(format!(
                    "samples/sample{}.exe",
                    downloaded_vx.load(Ordering::SeqCst)
                ))
                .unwrap();

                io::copy(&mut resbytes, &mut out).unwrap();

                if pause_vx.load(Ordering::SeqCst) == true {
                    loop {
                        if pause_vx.load(Ordering::SeqCst) == false {
                            break;
                        }
                    }
                }

                pb_vx.println(format!(
                    "{} sample{} from VX Vault",
                    green_bold.apply_to("Downloaded"),
                    downloaded_vx.load(Ordering::SeqCst)
                ));
                pb_vx.inc(1);
                downloaded_vx.fetch_add(1, Ordering::SeqCst);
            }

            pb_vx.println(format!(
                "{} all samples from VX Vault have been downloaded",
                green_bold.apply_to("Done")
            ));
        }));
    }

    futures::future::join_all(handles).await;

    if Path::new("temp/").exists() {
        fs::remove_dir_all("temp/").unwrap();
    }
}

async fn backup() {
    if !Path::new("samples/").exists() {
        println!("Cannot find the samples directory, quitting...");
        return;
    }

    let samples = fs::read_dir("samples/").unwrap();
    let samplescount = fs::read_dir("samples/").unwrap().count();

    let mut handles = vec![];

    let pb = ProgressBar::new(samplescount as u64);
    pb.set_style(
        ProgressStyle::with_template("{prefix.cyan.bold} [{bar:57}] {pos}/{len}")
            .unwrap()
            .progress_chars("=> "),
    );
    pb.set_prefix("Backupping");

    for sample in samples {
        let pb_clone = pb.clone();
        handles.push(task::spawn(async move {
            let sample_copy = sample.as_ref().unwrap();

            let green_bold = Style::new().green().bold();
            let red_bold = Style::new().red().bold();

            if sample_copy.path().extension().unwrap().to_str().unwrap() != "exe" {
                pb_clone.println(format!(
                    "{} {} is already backupped",
                    green_bold.apply_to("Backupped"),
                    sample
                        .as_ref()
                        .unwrap()
                        .path()
                        .file_stem()
                        .unwrap()
                        .to_str()
                        .unwrap()
                ));
                pb_clone.inc(1);
                return;
            }

            let data: &[u8] = &match fs::read(sample_copy.path()) {
                Ok(d) => d,
                Err(_) => {
                    pb_clone.println(format!(
                        "{} cannot read {}, skipping file",
                        red_bold.apply_to("Error"),
                        sample_copy.path().file_stem().unwrap().to_str().unwrap()
                    ));
                    pb_clone.inc(1);
                    return;
                }
            };

            let key = GenericArray::from([
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]);
            let cipher = Aes256GcmSiv::new(&key);
            let nonce = Nonce::from_slice(b"malwarefiles");

            let encrypted = cipher.encrypt(nonce, data).unwrap();

            let mut bytes: &[u8] = &encrypted;

            let mut out = fs::OpenOptions::new()
                .write(true)
                .open(sample_copy.path())
                .unwrap();

            io::copy(&mut bytes, &mut out).unwrap();

            match fs::rename(
                sample_copy.path().display().to_string(),
                format!(
                    "{}/{}.backup",
                    sample_copy.path().parent().unwrap().to_str().unwrap(),
                    sample_copy.path().file_stem().unwrap().to_str().unwrap()
                ),
            ) {
                Ok(()) => (),
                Err(_) => {
                    pb_clone.println(format!(
                        "{} cannot rename {}, skipping file",
                        red_bold.apply_to("Error"),
                        sample_copy.path().file_stem().unwrap().to_str().unwrap()
                    ));
                    pb_clone.inc(1);
                    return;
                }
            };

            pb_clone.println(format!(
                "{} {}",
                green_bold.apply_to("Backupped"),
                sample_copy.path().file_stem().unwrap().to_str().unwrap()
            ));
            pb_clone.inc(1);
        }));
    }
    futures::future::join_all(handles).await;
}

async fn restore() {
    if !Path::new("samples/").exists() {
        println!("Cannot find the samples directory, quitting...");
        return;
    }

    let samples = fs::read_dir("samples/").unwrap();
    let samplescount = fs::read_dir("samples/").unwrap().count();

    let mut handles = vec![];

    let pb = ProgressBar::new(samplescount as u64);
    pb.set_style(
        ProgressStyle::with_template("{prefix.cyan.bold} [{bar:57}] {pos}/{len}")
            .unwrap()
            .progress_chars("=> "),
    );
    pb.set_prefix("Restoring");

    for sample in samples {
        let pb_clone = pb.clone();
        handles.push(task::spawn(async move {
            let sample_copy = sample.as_ref().unwrap();

            let green_bold = Style::new().green().bold();
            let red_bold = Style::new().red().bold();

            if sample_copy.path().extension().unwrap().to_str().unwrap() != "backup" {
                pb_clone.println(format!(
                    "{} {} is already restored",
                    green_bold.apply_to("Restored"),
                    sample
                        .as_ref()
                        .unwrap()
                        .path()
                        .file_stem()
                        .unwrap()
                        .to_str()
                        .unwrap()
                ));
                pb_clone.inc(1);
                return;
            }

            match fs::rename(
                sample_copy.path().display().to_string(),
                format!(
                    "{}/{}.exe",
                    sample_copy.path().parent().unwrap().to_str().unwrap(),
                    sample_copy.path().file_stem().unwrap().to_str().unwrap()
                ),
            ) {
                Ok(()) => (),
                Err(_) => {
                    pb_clone.println(format!(
                        "{} cannot rename {}, skipping file",
                        red_bold.apply_to("Error"),
                        sample_copy.path().file_stem().unwrap().to_str().unwrap()
                    ));
                    pb_clone.inc(1);
                    return;
                }
            };

            let data: &[u8] = &fs::read(format!(
                "{}/{}.exe",
                sample_copy.path().parent().unwrap().to_str().unwrap(),
                sample_copy.path().file_stem().unwrap().to_str().unwrap()
            ))
            .unwrap();

            let key = GenericArray::from([
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]);
            let cipher = Aes256GcmSiv::new(&key);
            let nonce = Nonce::from_slice(b"malwarefiles");

            let decrypted = match cipher.decrypt(nonce, data) {
                Ok(d) => d,
                Err(_) => {
                    pb_clone.println(format!(
                        "{} cannot decrypt {}, skipping file",
                        red_bold.apply_to("Error"),
                        sample_copy.path().file_stem().unwrap().to_str().unwrap()
                    ));
                    pb_clone.inc(1);
                    return;
                }
            };

            let mut out = fs::OpenOptions::new()
                .write(true)
                .open(format!(
                    "{}/{}.exe",
                    sample_copy.path().parent().unwrap().to_str().unwrap(),
                    sample_copy.path().file_stem().unwrap().to_str().unwrap()
                ))
                .unwrap();

            let mut bytes: &[u8] = &decrypted;

            io::copy(&mut bytes, &mut out).unwrap();

            pb_clone.println(format!(
                "{} {}",
                green_bold.apply_to("Restored"),
                sample_copy.path().file_stem().unwrap().to_str().unwrap()
            ));
            pb_clone.inc(1);
        }));
    }
    futures::future::join_all(handles).await;
}

fn run() {
    let samples = fs::read_dir("samples/").unwrap();
    for sample in samples {
        if sample
            .as_ref()
            .unwrap()
            .path()
            .extension()
            .unwrap()
            .to_str()
            .unwrap()
            == "backup"
        {
            println!(
                "{} seems to be a backup, try restoring the files first",
                sample
                    .as_ref()
                    .unwrap()
                    .path()
                    .file_stem()
                    .unwrap()
                    .to_str()
                    .unwrap()
            );
            continue;
        }

        match Command::new(sample.as_ref().unwrap().path().display().to_string()).spawn() {
            Ok(c) => c,
            Err(e) => {
                println!(
                    "Something went wrong trying to run {}\nError: {}\n",
                    sample
                        .as_ref()
                        .unwrap()
                        .path()
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap(),
                    e
                );
                continue;
            }
        };
    }
}
