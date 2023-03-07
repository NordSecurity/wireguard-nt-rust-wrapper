#[cfg(any(windows, doc))]
#[cfg_attr(docsrs, doc(cfg(windows)))]
pub mod adapter;

#[cfg(any(windows, doc))]
#[cfg_attr(docsrs, doc(cfg(windows)))]
pub mod lib;

#[cfg(any(windows, doc))]
#[cfg_attr(docsrs, doc(cfg(windows)))]
pub mod log;

#[cfg(any(windows, doc))]
#[cfg_attr(docsrs, doc(cfg(windows)))]
pub mod util;

#[cfg(any(windows, doc))]
#[cfg_attr(docsrs, doc(cfg(windows)))]
pub mod wireguard_nt_raw;
