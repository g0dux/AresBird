use std::sync::Arc;

use ares_plugin_api::PluginRegistry;

use crate::active::ActiveMisconfigModule;
use crate::asn::AsnModule;
use crate::discover::DiscoverModule;
use crate::fingerprint::FingerprintModule;
use crate::path::PathModule;
use crate::recon::ReconModule;
use crate::scan::ScanModule;
use crate::service::ServiceModule;
use crate::talk::TalkModule;

pub fn builtin_registry() -> PluginRegistry {
    let mut reg = PluginRegistry::new();
    reg.register(Arc::new(DiscoverModule));
    reg.register(Arc::new(ScanModule));
    reg.register(Arc::new(ServiceModule));
    reg.register(Arc::new(FingerprintModule));
    reg.register(Arc::new(ReconModule));
    reg.register(Arc::new(TalkModule));
    reg.register(Arc::new(ActiveMisconfigModule));
    reg.register(Arc::new(PathModule));
    reg.register(Arc::new(AsnModule));
    reg
}
