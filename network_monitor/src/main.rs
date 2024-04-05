extern crate pcap;
extern crate pnet;

use pcap::{Capture, Device};
use std::path::Path;

use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::arp::ArpPacket;

use std::time::{Instant, Duration};

fn handle_ipv4_packet(packet: &Ipv4Packet) -> (String, String, String) {
    let source = packet.get_source();
    let destination = packet.get_destination();
    let size = packet.get_total_length();
    // println!("{:<35} | {:<35} | {:<15}", 
    //          format!("IPv4 Source: {}", source), 
    //          format!("Destination: {}", destination), 
    //          format!("Size: {}", size));
    return (source.to_string(), destination.to_string(), size.to_string());
}

fn handle_ipv6_packet(packet: &Ipv6Packet) -> (String, String, String) {
    let source = packet.get_source();
    let destination = packet.get_destination();
    let size = packet.get_payload_length();
    // println!("{:<40} {:<40} {:<15}", 
    //          format!("IPv6 Source: {}", source), 
    //          format!("Destination: {}", destination), 
    //          format!("Size: {}", size));
    return (source.to_string(), destination.to_string(), size.to_string());
}

fn handle_arp_packet(packet: &ArpPacket) -> (String, String, String) {
    let source = packet.get_sender_proto_addr();
    let destination = packet.get_target_proto_addr();
    let size = packet.packet().len();
    // println!("{:<35} | {:<35} | {:<15}", 
            // format!("IPv4 Source: {}", source), 
            // format!("Destination: {}", destination), 
            // format!("Size: {}", size));
    return (source.to_string(), destination.to_string(), size.to_string());
}

fn handle_ethernet_frame(frame: &EthernetPacket) -> (String, String, String) {
    let mut packet_info: (String, String, String) = ("".to_string(), "".to_string(), "".to_string());
    match frame.get_ethertype() {
        pnet::packet::ethernet::EtherTypes::Ipv4 => {
            if let Some(packet) = Ipv4Packet::new(frame.payload()) {
                packet_info = handle_ipv4_packet(&packet);
            }
        }
        pnet::packet::ethernet::EtherTypes::Ipv6 => {
            if let Some(packet) = Ipv6Packet::new(frame.payload()) {
                packet_info = handle_ipv6_packet(&packet);
            }
        }
        pnet::packet::ethernet::EtherTypes::Arp => {
            if let Some(packet) = ArpPacket::new(frame.payload()) {
                packet_info = handle_arp_packet(&packet);
            }
        }
        _ => {
            println!("Unknown packet format");
        }
    }
    // Return the packet info
    return packet_info;
}

fn main() {
    
    let device = Device::lookup().unwrap().unwrap();
    let mut cap = Capture::from_device(device.clone())
        .unwrap()
        .open()
        .unwrap();
    
    // Get current device ip address
    let current_device_ip = device.addresses[2].addr.to_string();
    println!("Device IP address: {:?}", current_device_ip);

    let path = Path::new("output.pcap");
    let mut save_file = cap.savefile(path).unwrap();

    let mut uploaded: u32 = 0;
    let mut downloaded: u32 = 0;
    let mut last_print = Instant::now();

    while let Ok(packet) = cap.next_packet() {
        let ethernet = EthernetPacket::new(packet.data).unwrap();
        let packet_info = handle_ethernet_frame(&ethernet);

        // Check the source IP and update uploaded and downloaded
        if packet_info.0 == current_device_ip {
            uploaded += packet_info.2.parse::<u32>().unwrap_or(0);
        } else {
            downloaded += packet_info.2.parse::<u32>().unwrap_or(0);
        }

        // Print uploaded and downloaded every second
        if last_print.elapsed() >= Duration::from_secs(1) {
            println!("Upload: {} bytes/sec", uploaded);
            println!("Download: {} bytes/sec", downloaded);
            uploaded = 0;
            downloaded = 0;
            last_print = Instant::now();
        }

        save_file.write(&packet);
    }
}