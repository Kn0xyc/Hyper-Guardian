use quick_xml::de::from_str;

use crate::models::{Asset, Evidence, Finding, NormalizedScan, Service};

#[derive(Debug, serde::Deserialize)]
struct NmapRun {
    #[serde(rename = "host", default)]
    hosts: Vec<NmapHost>,
}

#[derive(Debug, serde::Deserialize)]
struct NmapHost {
    #[serde(rename = "address")]
    address: NmapAddress,
    #[serde(default)]
    hostnames: Option<NmapHostnames>,
    #[serde(default)]
    ports: Option<NmapPorts>,
}

#[derive(Debug, serde::Deserialize)]
struct NmapAddress {
    #[serde(rename = "@addr")]
    addr: String,
}

#[derive(Debug, serde::Deserialize)]
struct NmapHostnames {
    #[serde(rename = "hostname", default)]
    hostnames: Vec<NmapHostname>,
}

#[derive(Debug, serde::Deserialize)]
struct NmapHostname {
    #[serde(rename = "@name")]
    name: String,
}

#[derive(Debug, serde::Deserialize)]
struct NmapPorts {
    #[serde(rename = "port", default)]
    ports: Vec<NmapPort>,
}

#[derive(Debug, serde::Deserialize)]
struct NmapPort {
    #[serde(rename = "@portid")]
    portid: u16,
    #[serde(rename = "@protocol")]
    protocol: String,
    state: NmapState,
    #[serde(default)]
    service: Option<NmapService>,
}

#[derive(Debug, serde::Deserialize)]
struct NmapState {
    #[serde(rename = "@state")]
    state: String,
}

#[derive(Debug, serde::Deserialize)]
struct NmapService {
    #[serde(rename = "@name")]
    name: String,
}

pub fn parse_nmap_xml(xml: &str) -> anyhow::Result<NormalizedScan> {
    let run: NmapRun = from_str(xml)?;
    let mut scan = NormalizedScan {
        assets: vec![],
        services: vec![],
        findings: vec![],
        evidence: vec![],
    };

    for host in run.hosts {
        let hostname = host
            .hostnames
            .as_ref()
            .and_then(|h| h.hostnames.first().map(|e| e.name.clone()));
        scan.assets.push(Asset {
            hostname,
            ip: host.address.addr.clone(),
        });

        if let Some(ports) = host.ports {
            for p in ports.ports {
                if p.state.state == "open" {
                    scan.services.push(Service {
                        ip: host.address.addr.clone(),
                        port: p.portid,
                        protocol: p.protocol,
                        service_name: p.service.as_ref().map(|s| s.name.clone()),
                    });
                    let key = format!("{}:{}", host.address.addr, p.portid);
                    scan.findings.push(Finding {
                        key: key.clone(),
                        severity: "info".to_string(),
                        title: format!("Open port {}", p.portid),
                        description: "Service exposé détecté par Nmap".to_string(),
                    });
                    scan.evidence.push(Evidence {
                        finding_key: key,
                        raw: format!("open {} {}", p.protocol, p.portid),
                    });
                }
            }
        }
    }

    Ok(scan)
}

#[cfg(test)]
mod tests {
    use super::parse_nmap_xml;

    #[test]
    fn parse_nmap_xml_extracts_assets_and_open_ports() {
        let xml = include_str!("../../examples/nmap_sample.xml");
        let scan = parse_nmap_xml(xml).expect("parse should work");
        assert_eq!(scan.assets.len(), 1);
        assert_eq!(scan.services.len(), 1);
        assert_eq!(scan.findings.len(), 1);
        assert_eq!(scan.assets[0].ip, "192.168.1.10");
        assert_eq!(scan.services[0].port, 80);
    }

    #[test]
    fn normalization_creates_evidence_per_finding() {
        let xml = include_str!("../../examples/nmap_sample.xml");
        let scan = parse_nmap_xml(xml).expect("parse should work");
        assert_eq!(scan.findings.len(), scan.evidence.len());
        assert!(scan.evidence[0].raw.contains("open tcp 80"));
    }
}
