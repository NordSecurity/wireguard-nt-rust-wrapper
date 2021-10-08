#!/bin/bash
bindgen \
--allowlist-function "WireGuard.*" \
--allowlist-type "WIREGUARD_.*" \
--dynamic-loading wireguard \
wireguard_nt/wireguard.h > src/wireguard_nt_raw.rs