extern crate pcap;
extern crate pnet;
extern crate chrono;

use pcap::{Capture, Device};
use pnet::packet::ethernet::EthernetPacket;
use std::path::Path;
use std::fs::File;
use std::io::prelude::*;

use std::time::{Instant, Duration};
use chrono::Local;
use chrono::format::strftime::StrftimeItems;
//ctrlc handling
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use ctrlc;

// CSV writing
use std::fs::OpenOptions;
use std::error::Error;
mod packet_handler;

fn main(){
    

    let device = Device::lookup().unwrap().unwrap();
    let mut cap = Capture::from_device(device.clone())
        .unwrap()
        .open()
        .unwrap();
    

    // Get current device ip address
    //Wish: I changed the index of 'device.addresses' from 2 to 1 to work on my mac
    let current_device_ip = device.addresses[2].addr.to_string();
    println!("Device IP address: {:?}", current_device_ip);


    let pcap_path = Path::new("output.pcap");
    let mut save_file = cap.savefile(pcap_path).unwrap();
    let mut csv_file = match File::create(pcap_path) {
        Ok(file) => file,
        Err(err) => {
            println!("Error creating pcap file: {}", err);
            return; // Exit if creating the file fails
        }
    };

    let mut uploaded: u32 = 0;
    let mut downloaded: u32 = 0;
    let mut last_print = Instant::now();
    let mut csv_data = String::new();



    //ctrlc handling
    // Create a flag to indicate if the program should keep running
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    // Handle Ctrl-C signal
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");
    

    //create a csv file
    // Open the CSV file
    let mut csv_file = OpenOptions::new()
    .write(true)
    .append(true)
    .create(true)
    .open("data.csv");

    // Handle the result to get the file handle
    let mut csv_file = match csv_file {
    Ok(file) => file,
    Err(e) => {
        eprintln!("Error opening CSV file: {}", e);
        return; // Exit if opening the file fails
    }
    };

    while running.load(Ordering::SeqCst) {
        match cap.next_packet() {
            Ok(packet) => {
                let ethernet = EthernetPacket::new(packet.data).unwrap();
                let packet_info = packet_handler::handle_ethernet_frame(&ethernet);

                save_file.write(&packet);
    
                // Check the source IP and update uploaded and downloaded
                if packet_info.0 == current_device_ip {
                    uploaded += packet_info.2.parse::<u32>().unwrap_or(0);
                } else {
                    downloaded += packet_info.2.parse::<u32>().unwrap_or(0);
                }
    
                // Print uploaded and downloaded every second
                if last_print.elapsed() >= Duration::from_secs(1) {
                    let time = Local::now();
                    println!("{}", time.format("%Y-%m-%d][%H:%M:%S"));
                    println!("Upload: {} bytes/sec", uploaded);
                    println!("Download: {} bytes/sec", downloaded);
    
                    //reset counter
                    uploaded = 0;
                    downloaded = 0;
                    last_print = Instant::now();
    
                }

                // Prepare data for PCAP
                let mut formatter = StrftimeItems::new("%Y-%m-%d %H:%M:%S");
                let csv_row = format!("{},{},{},{}",
                    Local::now().format_with_items(formatter).to_string(),
                    packet_info.0, packet_info.1, packet_info.2);
                //csv_data.push_str(&csv_row);
                if let Err(e) = writeln!(csv_file, "{}", &csv_row) {
                    eprintln!("Couldn't write to file: {}", e);
                }

        
            }
            Err(_) => {
                // Error handling if packet retrieval fails
                // You can choose to break the loop or handle the error in another way
                break;
            }
        }
    }

    println!("data are stored in 'data.csv' and 'output.pcap'! \n
            thank you for using! Bye!\n");


}