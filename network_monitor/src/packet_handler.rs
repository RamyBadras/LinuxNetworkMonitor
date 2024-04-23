extern crate pnet;
extern crate pcap;

use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use crate::pnet::packet::Packet;

pub fn handle_ipv4_packet(packet: &Ipv4Packet) -> (String, String, String, String) {
    let source = packet.get_source();
    let destination = packet.get_destination();
    let size = packet.get_total_length();
    let protocol = packet.get_next_level_protocol();
    // println!("{:<35} | {:<35} | {:<15} | {:<15}", 
    //         format!("IPv4 Source: {}", source), 
    //         format!("Destination: {}", destination), 
    //         format!("Size: {}", size),
    //         format!("Next Level Protocol: {}", protocol));

    return (source.to_string(), destination.to_string(), size.to_string(), protocol.to_string());
}

pub fn handle_ipv6_packet(packet: &Ipv6Packet) -> (String, String, String, String) {
    let source = packet.get_source();
    let destination = packet.get_destination();
    let size = packet.get_payload_length();
    let protocol = packet.get_next_header();
    // println!("{:<40} | {:<40} | {:<15} | {:<15}", 
    //          format!("IPv6 Source: {}", source), 
    //          format!("Destination: {}", destination), 
    //          format!("Size: {}", size),
    //          format!("Next Header: {}", protocol));
    return (source.to_string(), destination.to_string(), size.to_string(), protocol.to_string());
}

pub fn handle_arp_packet(packet: &ArpPacket) -> (String, String, String, String) {
    let source = packet.get_sender_proto_addr();
    let destination = packet.get_target_proto_addr();
    let size = packet.packet().len();
    // println!("{:<35} | {:<35} | {:<15}", 
    //         format!("IPv4 Source: {}", source), 
    //         format!("Destination: {}", destination), 
    //         format!("Size: {}", size));
    return (source.to_string(), destination.to_string(), size.to_string(), "".to_string());
}

pub(crate) fn handle_ethernet_frame(frame: &EthernetPacket) -> (String, String, String, String, String) {
    let mut packet_info: (String, String, String, String, String) = ("".to_string(), "".to_string(), "".to_string(), "".to_string(), "".to_string());
    match frame.get_ethertype() {
        pnet::packet::ethernet::EtherTypes::Ipv4 => {
            if let Some(packet) = Ipv4Packet::new(frame.payload()) {
                let (source, destination, size, protocol) = handle_ipv4_packet(&packet);
                packet_info = (source, destination, size, protocol, "IPv4".to_string());
            }
        }
        pnet::packet::ethernet::EtherTypes::Ipv6 => {
            if let Some(packet) = Ipv6Packet::new(frame.payload()) {
                let (source, destination, size, protocol) = handle_ipv6_packet(&packet);
                packet_info = (source, destination, size, protocol, "IPv6".to_string());
            }
        }
        pnet::packet::ethernet::EtherTypes::Arp => {
            if let Some(packet) = ArpPacket::new(frame.payload()) {
                let (source, destination, size, _) = handle_arp_packet(&packet);
                packet_info = (source, destination, size, "".to_string(), "ARP".to_string());
            }
        }
        _ => {
            println!("Unknown packet format");
        }
    }
    // Return the packet info
    return packet_info;
}

pub fn handle_tcp_packet(packet: &TcpPacket) -> String {
    let destination_port = packet.get_destination();
    match destination_port {
        80 => "HTTP".to_string(),
        443 => "HTTPS".to_string(),
        22 => "SSH".to_string(),
        21 => "FTP".to_string(),
        25 => "SMTP".to_string(),
        110 => "POP3".to_string(),
        _ => format!("Port {}", destination_port),
    }
}

pub fn handle_udp_packet(packet: &UdpPacket) -> String {
    let destination_port = packet.get_destination();
    match destination_port {
        53 => "DNS".to_string(),
        67 => "DHCP".to_string(),
        68 => "DHCP".to_string(),
        _ => format!("Port {}", destination_port),
    }
}
