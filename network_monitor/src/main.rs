extern crate pcap;
extern crate argparse;

use pcap::{Capture, Device}; 

fn main() {

    let mut cap = Device::lookup().unwrap().unwrap().open().unwrap();
    let chosen_device = Device::lookup().unwrap().unwrap();

    while let Ok(packet) = cap.next_packet() {
        
        println!("From device {}, received packet with length {}", chosen_device.name, packet.len());

    }

}
