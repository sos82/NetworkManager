#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#[allow(improper_ctypes)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

mod com_redhat;

use std::convert::From;
use std::env;
use std::ffi::CStr;
use std::fmt;
use std::fs;
use std::io::prelude::*;
use std::marker::Send;
use std::ops::Fn;
use std::ops::{Deref, Drop};
use std::ptr::null_mut;
use std::sync::Arc;
use std::thread;

#[repr(u32)]
#[derive(Debug)]
enum NDHCP4Event {
    N_DHCP4_CLIENT_EVENT_DOWN,
    N_DHCP4_CLIENT_EVENT_OFFER,
    N_DHCP4_CLIENT_EVENT_GRANTED,
    N_DHCP4_CLIENT_EVENT_RETRACTED,
    N_DHCP4_CLIENT_EVENT_EXTENDED,
    N_DHCP4_CLIENT_EVENT_EXPIRED,
    N_DHCP4_CLIENT_EVENT_CANCELLED,
    N_DHCP4_CLIENT_EVENT_LOG,
}

impl From<u32> for NDHCP4Event {
    fn from(u: u32) -> Self {
        unsafe { std::mem::transmute::<u32, NDHCP4Event>(u) }
    }
}

impl fmt::Display for NDHCP4Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

struct NDHCP4ClientConfig(*mut NDhcp4ClientConfig);

impl NDHCP4ClientConfig {
    fn new(ifindex: i32, mac_addr: &Vec<u8>) -> Result<NDHCP4ClientConfig, &'static str> {
        let mut configp = null_mut();

        unsafe {
            if n_dhcp4_client_config_new(&mut configp) == 0 {
                let bcast_mac_addr: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
                let mut client_id = vec![0x1];

                n_dhcp4_client_config_set_ifindex(configp, ifindex);
                n_dhcp4_client_config_set_transport(configp, N_DHCP4_TRANSPORT_ETHERNET);
                n_dhcp4_client_config_set_mac(configp, mac_addr.as_ptr(), 6);
                n_dhcp4_client_config_set_broadcast_mac(configp, bcast_mac_addr.as_ptr(), 6);

                client_id.extend(mac_addr);
                n_dhcp4_client_config_set_client_id(
                    configp,
                    client_id.as_ptr(),
                    client_id.len() as u64,
                );

                Ok(NDHCP4ClientConfig(configp))
            } else {
                Err("n_dhcp4_client_config_new() failed")
            }
        }
    }
}

impl Deref for NDHCP4ClientConfig {
    type Target = *mut NDhcp4ClientConfig;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for NDHCP4ClientConfig {
    fn drop(&mut self) {
        unsafe {
            n_dhcp4_client_config_free(self.0);
        }
    }
}

struct NDHCP4Client(Arc<*mut NDhcp4Client>);

impl NDHCP4Client {
    fn new(config: NDHCP4ClientConfig) -> Result<NDHCP4Client, &'static str> {
        let mut client = null_mut();

        unsafe {
            if n_dhcp4_client_new(&mut client, *config) == 0 {
                n_dhcp4_client_set_log_level(client, 7);

                let mut probe_config = null_mut();
                if n_dhcp4_client_probe_config_new(&mut probe_config) != 0 {
                    return Err("n_dhcp4_client_probe_config_new() failed");
                }

                n_dhcp4_client_probe_config_set_start_delay(probe_config, 1);

                let mut probe = null_mut();
                if n_dhcp4_client_probe(client, &mut probe, probe_config) != 0 {
                    return Err("n_dhcp4_client_probe() failed");
                }

                Ok(NDHCP4Client(Arc::new(client)))
            } else {
                Err("invalid config")
            }
        }
    }

    fn run<F>(&self, f: F)
    where
        F: Fn(NDHCP4Event, Option<&str>),
    {
        unsafe {
            loop {
                if n_dhcp4_client_dispatch(*self.0) == 0 {
                    let mut event = null_mut();

                    if n_dhcp4_client_pop_event(*self.0, &mut event) == 0 && event != null_mut() {
                        let mut log = None;
                        let event_enum = NDHCP4Event::from((*event).event);

                        if let NDHCP4Event::N_DHCP4_CLIENT_EVENT_LOG = event_enum {
                            log = if let Ok(s) =
                                CStr::from_ptr((*event).__bindgen_anon_1.log.message).to_str()
                            {
                                Some(s)
                            } else {
                                None
                            };
                        }

                        f(event_enum, log);
                    }
                }
            }
        }
    }
}

impl Drop for NDHCP4Client {
    fn drop(&mut self) {
        unsafe {
            n_dhcp4_client_unref(*self.0);
        }
    }
}

unsafe impl Send for NDHCP4Client {}

struct DHCPClientVarlink;

impl com_redhat::VarlinkInterface for DHCPClientVarlink {
    fn ping(&self, call: &mut dyn com_redhat::Call_Ping, ping: String) -> varlink::Result<()> {
        println!("Varlink: {}", ping);
        call.reply(ping)
    }
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    if let Some(iface) = env::args().skip(1).next() {
        let mut file = fs::File::open(format!("/sys/class/net/{}/address", iface))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        contents.pop();

        eprintln!(
            "dhcp-client started on {} with mac_addr {}",
            iface, contents
        );

        let mac_addr = contents.into_bytes();
        let mut client_id = Vec::from(mac_addr.clone());
        client_id.insert(0, 0x1);

        let mut file = fs::File::open(format!("/sys/class/net/{}/ifindex", iface))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        contents.pop();
        let ifindex = contents.parse::<i32>().unwrap();

        let client =
            NDHCP4Client::new(NDHCP4ClientConfig::new(ifindex, &mac_addr).unwrap()).unwrap();

        let handle = thread::spawn(move || {
            client.run(|event, log_msg| match event {
                NDHCP4Event::N_DHCP4_CLIENT_EVENT_LOG if log_msg.is_some() => {
                    println!("{}", log_msg.unwrap());
                }
                _ => println!("Event: {}", event),
            })
        });

        let service = varlink::VarlinkService::new(
            "com.redhat.dhcp",
            "test service",
            "0.1",
            "https://gitlab.freedesktop.org/NetworkManager/NetworkManager",
            vec![Box::new(com_redhat::new(Box::new(DHCPClientVarlink)))],
        );

        println!("Start varlink interface");
        if let Err(e) = varlink::listen(
            service,
            "unix:com.redhat.dhcp",
            &varlink::ListenConfig {
                idle_timeout: 0,
                ..Default::default()
            },
        ) {
            eprintln!("{}", e);
        }

    // handle.join();
    } else {
        eprintln!("no interface name supplied");
    }
    Ok(())
}
