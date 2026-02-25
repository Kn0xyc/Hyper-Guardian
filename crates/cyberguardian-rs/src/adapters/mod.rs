use crate::{models::NormalizedScan, parser::parse_nmap_xml, security::run_command_allowlisted};

#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub target: String,
    pub profile: String,
}

#[async_trait::async_trait]
pub trait ToolAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    async fn run(&self, req: ScanRequest) -> anyhow::Result<NormalizedScan>;
}

pub struct NmapAdapter;

#[async_trait::async_trait]
impl ToolAdapter for NmapAdapter {
    fn name(&self) -> &'static str {
        "nmap"
    }

    async fn run(&self, req: ScanRequest) -> anyhow::Result<NormalizedScan> {
        let payload = sample_nmap_xml_for_target(&req.target);
        let (cmd, args, allowed): (&str, Vec<String>, Vec<&str>) = if cfg!(target_os = "windows") {
            ("cmd", vec!["/C".to_string(), payload], vec!["cmd"])
        } else {
            ("echo", vec![payload], vec!["echo"])
        };

        let xml = run_command_allowlisted(cmd, &args, &allowed, 10).await?;
        parse_nmap_xml(&xml)
    }
}

pub struct NucleiAdapter;
pub struct ZapAdapter;
pub struct NiktoAdapter;
pub struct FfufAdapter;
pub struct AmassAdapter;

fn sample_nmap_xml_for_target(target: &str) -> String {
    format!(
        "<nmaprun><host><address addr=\"{}\"/><hostnames><hostname name=\"demo.local\"/></hostnames><ports><port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/><service name=\"http\"/></port></ports></host></nmaprun>",
        target
    )
}
