use cups_rs::{Dnssd, DnssdResolveEvent};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn main() -> cups_rs::Result<()> {
    let (error_sender, error_receiver) = mpsc::channel();
    let (browse_sender, browse_receiver) = mpsc::channel();
    let (resolve_sender, resolve_receiver) = mpsc::channel::<DnssdResolveEvent>();
    let dnssd = Dnssd::new(error_sender)?;
    let _ipp = dnssd.browse("_ipp-system._tcp", None, browse_sender.clone())?;
    let _ipps = dnssd.browse("_ipps-system._tcp", None, browse_sender)?;
    let mut resolvers = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);

    while Instant::now() < deadline {
        while let Ok(service) = browse_receiver.try_recv() {
            if service.added {
                resolvers.push(dnssd.resolve(&service, resolve_sender.clone())?);
            }
        }
        while let Ok(service) = resolve_receiver.try_recv() {
            println!(
                "{} {}:{} ({})",
                service.name, service.hostname, service.port, service.service_type
            );
            for (name, value) in service.txt {
                println!("  {name}={value}");
            }
        }
        while let Ok(error) = error_receiver.try_recv() {
            eprintln!("DNS-SD error: {error}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    Ok(())
}
