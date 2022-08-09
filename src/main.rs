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

    loop {
        print!("Do you want to\n(d)ownload\n(de)obfuscate\n");
        io::stdout().flush().unwrap();
        let mut startbuf = String::new();
        io::stdin().read_line(&mut startbuf).expect("Failed to read from stdin");
        let execute = startbuf.trim().to_string();
        if execute != "d" && execute != "de" {
            println!("Invalid option");
            continue;
        }

        if execute == "d" {
            download().await;
            return;
        }
        else if execute == "de" {
            deobfuscate();
            return;
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
            println!("Failed to get data from Malshare: Invalid API key or there is no quota remaining");
            loop {
                print!("Do you want to\n(q)uit\n(c)ontinue\n");
                io::stdout().flush().unwrap();
                let mut failbuf = String::new();
                io::stdin().read_line(&mut failbuf).expect("Failed to read from stdin");
                let answer = failbuf.trim().to_string();
                if answer != "q" && answer != "c" {
                    println!("Invalid answer");
                    continue;
                }
                if answer == "q" {
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

            let databytes : &mut [u8] = &mut data;

            let bytecount = databytes.iter_mut().count();
            let split = databytes.iter_mut().count() / 25;
            let mut splitcount = 0;
            let mut current = 0;

            for byte in databytes.iter_mut().take(bytecount) {
                    if current % split == 0 {
                        splitcount += 1;
                    }
                    let canadd = byte.checked_add(splitcount);
                    if canadd != None {
                        *byte += splitcount;
                    }
                    current += 1;
            }

            let mut samplebytes : &[u8] = databytes;

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

            let mut result : Vec<u8> = res.to_vec();
            let resbytes : &mut [u8] = &mut result;

            let bytecount = resbytes.iter_mut().count();
            let split = resbytes.iter_mut().count() / 25;
            let mut splitcount = 0;
            let mut current = 0;

            for byte in resbytes.iter_mut().take(bytecount) {
                    if current % split == 0 {
                        splitcount += 1;
                    }
                    let canadd = byte.checked_add(splitcount);
                    if canadd != None {
                        *byte += splitcount;
                    }
                    current += 1;
            }
        
            let mut bytes : &[u8] = resbytes;
        
            let mut out = File::create(format!("samples/sample{}", downloaded_clone.load(Ordering::SeqCst))).unwrap();

            io::copy(&mut bytes, &mut out).unwrap();

            println!("Downloaded file {}/{} from Malshare", downloaded_clone.load(Ordering::SeqCst), count_clone.load(Ordering::SeqCst));
            downloaded_clone.fetch_add(1, Ordering::SeqCst);
        }
    }));

    futures::future::join_all(handles).await;
    fs::remove_dir_all("temp/").unwrap();
}

fn deobfuscate() {
    if !Path::new("samples/").exists() {
        println!("Cannot find the samples directory, quitting...");
        return;
    }

    let samples = fs::read_dir("samples/").unwrap();
    for sample in samples {
        if !sample.as_ref().unwrap().path().extension().is_none() {
            println!("{} is already deobfuscated", sample.unwrap().path().file_name().unwrap().to_str().unwrap());
            continue;
        }

        let _ = match fs::rename(sample.as_ref().unwrap().path().display().to_string(), format!("{}.exe", sample.as_ref().unwrap().path().display())) {
            Ok(res) => res,
            Err(_) => {
                println!("Cannot rename {}, skipping file renaming", sample.unwrap().path().file_name().unwrap().to_str().unwrap());
                continue;
            }
        };

        let data: &mut [u8] = &mut fs::read(format!("{}.exe", sample.as_ref().unwrap().path().display())).unwrap();
        
        let bytecount = data.iter_mut().count();
        let split = data.iter_mut().count() / 25;
        let mut splitcount = 0;
        let mut current = 0;

        for byte in data.iter_mut().take(bytecount) {
                if current % split == 0 {
                    splitcount += 1;
                }
                let cansub = byte.checked_sub(splitcount);
                if cansub != None {
                    *byte -= splitcount;
                }
                current += 1;
        }
        
        let mut out = fs::OpenOptions::new().write(true).open(format!("{}.exe", sample.as_ref().unwrap().path().display())).unwrap();

        let mut bytes : &[u8] = &data;

        io::copy(&mut bytes, &mut out).unwrap();

        println!("Deobfuscated {}", sample.unwrap().path().file_name().unwrap().to_str().unwrap())
    }
}