"""Synthetic incident catalog for the AIOps RCA MVP.

The catalog intentionally models a small but complete universe. The agent does
not connect to real infrastructure; each template contains the signals needed
to generate realistic alerts, logs, metrics, topology, recent changes, and
evaluation ground truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


Pattern = dict[str, Any]


@dataclass(frozen=True)
class IncidentTemplate:
    key: str
    category: str
    root_cause: str
    severity: str
    alert_message: str
    summary: str
    impact: str
    topology_role: str
    impacted_service: str
    change_events: tuple[Pattern, ...]
    log_events: tuple[Pattern, ...]
    noise_events: tuple[Pattern, ...]
    metric_series: tuple[Pattern, ...]
    baseline: Pattern
    signatures: tuple[str, ...]
    symptoms: tuple[str, ...]
    missing_data: tuple[str, ...]
    verification_steps: tuple[str, ...]
    immediate_actions: tuple[str, ...]
    long_term_prevention: tuple[str, ...]


COMMON_TOPOLOGY = {
    "firewall": "FGT-HQ-01",
    "core_switch": "JUN-CORE-01",
    "access_switch": "ARUBA-ACC-03",
    "edge_router": "RTR-HQ-01",
    "dns_server": "DNS-HQ-01",
    "linux_server": "APP-LNX-01",
    "windows_server": "WIN-APP-01",
    "vmware_datastore": "DS-PRD-01",
    "vmware_cluster": "VCENTER-HCM-01",
    "identity_server": "IAM-PRD-01",
    "wazuh": "WAZUH-MGR-01",
    "internet_edge": "ISP-HCM-EDGE",
    "camera": "CAMERA-01",
}


TEMPLATES: tuple[IncidentTemplate, ...] = (
    IncidentTemplate(
        key="broadcast-loop-aruba",
        category="network",
        root_cause="Broadcast Loop on Aruba switch",
        severity="critical",
        alert_message="Broadcast storm and switch CPU high on access layer",
        summary="A recently enabled Aruba trunk port is followed by STP changes, MAC flapping, broadcast PPS surge, and downstream firewall load.",
        impact="Campus LAN users see intermittent loss and high latency on VLAN 120.",
        topology_role="access_switch",
        impacted_service="campus_lan",
        change_events=(
            {
                "offset": 0,
                "device_role": "access_switch",
                "action": "Enable trunk port 1/1/48 on ARUBA-ACC-03 without loop guard validation",
                "actor": "netops.admin",
            },
        ),
        log_events=(
            {
                "offset": 4,
                "source_role": "access_switch",
                "event_type": "stp_topology_change",
                "severity": "warning",
                "message": "STP topology change detected on VLAN 120 after port 1/1/48 came up",
                "role": "root_cause_candidate",
            },
            {
                "offset": 5,
                "source_role": "core_switch",
                "event_type": "mac_flapping",
                "severity": "critical",
                "message": "MAC addresses moving between ae1 and access uplink toward ARUBA-ACC-03",
                "role": "evidence",
            },
            {
                "offset": 6,
                "source_role": "access_switch",
                "event_type": "broadcast_storm",
                "severity": "critical",
                "message": "Broadcast PPS exceeds storm-control threshold on VLAN 120",
                "role": "evidence",
            },
            {
                "offset": 9,
                "source_role": "firewall",
                "event_type": "session_spike",
                "severity": "warning",
                "message": "FortiGate session creation rate spikes due to repeated ARP and broadcast traffic",
                "role": "symptom",
            },
            {
                "offset": 12,
                "source_role": "campus_lan",
                "event_type": "user_impact",
                "severity": "critical",
                "message": "Users report intermittent LAN outage on floor 3",
                "role": "impact",
            },
        ),
        noise_events=(
            {
                "offset": -7,
                "source_role": "dns_server",
                "event_type": "scheduled_zone_transfer",
                "severity": "info",
                "message": "Scheduled DNS zone transfer completed successfully",
            },
            {
                "offset": 8,
                "source_role": "linux_server",
                "event_type": "backup_job_completed",
                "severity": "info",
                "message": "Nightly application backup completed",
            },
        ),
        metric_series=(
            {"offset": -3, "source_role": "access_switch", "metric": "broadcast_pps", "value": 1200, "threshold": 50000, "unit": "pps", "phase": "before"},
            {"offset": 7, "source_role": "access_switch", "metric": "broadcast_pps", "value": 185000, "threshold": 50000, "unit": "pps", "phase": "during"},
            {"offset": 16, "source_role": "access_switch", "metric": "broadcast_pps", "value": 42000, "threshold": 50000, "unit": "pps", "phase": "after"},
            {"offset": -3, "source_role": "access_switch", "metric": "cpu_usage", "value": 34, "threshold": 85, "unit": "%", "phase": "before"},
            {"offset": 8, "source_role": "access_switch", "metric": "cpu_usage", "value": 96, "threshold": 85, "unit": "%", "phase": "during"},
            {"offset": 17, "source_role": "access_switch", "metric": "cpu_usage", "value": 62, "threshold": 85, "unit": "%", "phase": "after"},
        ),
        baseline={"broadcast_pps": 1200, "cpu_usage": 34, "normal_stp_changes_per_hour": 2},
        signatures=("broadcast", "storm", "loop", "stp_topology_change", "mac_flapping", "broadcast_storm", "trunk port", "loop guard"),
        symptoms=("High switch CPU", "MAC flapping", "Broadcast PPS spike", "Firewall session spike"),
        missing_data=("Physical loop confirmation on port 1/1/48", "Current STP state for VLAN 120"),
        verification_steps=("Check STP state and loop guard on ARUBA-ACC-03 port 1/1/48", "Confirm MAC flapping stops after isolating the port", "Verify broadcast PPS returns below storm-control threshold"),
        immediate_actions=("Isolate or shut the suspected access port after verification", "Keep core uplinks stable and monitor STP convergence", "Notify network operations before any config rollback"),
        long_term_prevention=("Enable BPDU guard and loop guard on edge ports", "Add pre-change validation for trunk enablement", "Alert on MAC flapping plus broadcast PPS correlation"),
    ),
    IncidentTemplate(
        key="mac-flapping-core",
        category="network",
        root_cause="MAC flapping on core switch",
        severity="major",
        alert_message="Core switch reports repeated MAC movement",
        summary="The core switch observes the same MAC addresses moving across redundant uplinks, pointing to an unstable L2 path.",
        impact="Users behind the affected VLAN experience intermittent packet loss.",
        topology_role="core_switch",
        impacted_service="campus_lan",
        change_events=(
            {
                "offset": -1,
                "device_role": "core_switch",
                "action": "Modify LACP member on ae1 during access switch migration",
                "actor": "netops.l2",
            },
        ),
        log_events=(
            {"offset": 2, "source_role": "core_switch", "event_type": "lacp_member_removed", "severity": "warning", "message": "ae1 member ge-0/0/2 removed from bundle", "role": "root_cause_candidate"},
            {"offset": 3, "source_role": "core_switch", "event_type": "mac_flapping", "severity": "major", "message": "MAC 00:16:3e:aa:01:20 moves between ae1 and ae2", "role": "evidence"},
            {"offset": 5, "source_role": "core_switch", "event_type": "duplicate_mac_detected", "severity": "major", "message": "Duplicate MAC events exceed baseline on VLAN 210", "role": "evidence"},
            {"offset": 8, "source_role": "campus_lan", "event_type": "packet_loss", "severity": "major", "message": "Packet loss reported for users on VLAN 210", "role": "impact"},
        ),
        noise_events=(
            {"offset": -4, "source_role": "wazuh", "event_type": "agent_keepalive", "severity": "info", "message": "Wazuh agent keepalive normal"},
        ),
        metric_series=(
            {"offset": -2, "source_role": "core_switch", "metric": "mac_move_count", "value": 2, "threshold": 30, "unit": "moves/min", "phase": "before"},
            {"offset": 4, "source_role": "core_switch", "metric": "mac_move_count", "value": 145, "threshold": 30, "unit": "moves/min", "phase": "during"},
            {"offset": 13, "source_role": "core_switch", "metric": "mac_move_count", "value": 18, "threshold": 30, "unit": "moves/min", "phase": "after"},
            {"offset": -2, "source_role": "core_switch", "metric": "packet_loss", "value": 0, "threshold": 5, "unit": "%", "phase": "before"},
            {"offset": 7, "source_role": "core_switch", "metric": "packet_loss", "value": 18, "threshold": 5, "unit": "%", "phase": "during"},
            {"offset": 15, "source_role": "core_switch", "metric": "packet_loss", "value": 2, "threshold": 5, "unit": "%", "phase": "after"},
        ),
        baseline={"mac_move_count": 2, "packet_loss": 0},
        signatures=("mac_flapping", "duplicate_mac", "mac movement", "lacp_member_removed", "ae1", "ae2"),
        symptoms=("MAC movement spike", "Duplicate MAC events", "Packet loss"),
        missing_data=("Interface bundle consistency check", "Current LACP state on ae1 and ae2"),
        verification_steps=("Check LACP state on core switch bundles", "Confirm MAC table stabilizes after fixing the member link", "Review access switch uplink mapping"),
        immediate_actions=("Stabilize the affected LACP member or remove it from service after verification", "Avoid changing both redundant paths at the same time"),
        long_term_prevention=("Add LACP migration checklist", "Alert on duplicate MAC plus LACP change correlation"),
    ),
    IncidentTemplate(
        key="fortigate-session-spike",
        category="network",
        root_cause="Fortigate session spike causing high CPU",
        severity="critical",
        alert_message="FortiGate CPU high with session table spike",
        summary="A new NAT policy is hit heavily, session setup rate rises sharply, and FortiGate CPU crosses critical threshold.",
        impact="Internet access becomes slow or intermittently unavailable for outbound users.",
        topology_role="firewall",
        impacted_service="internet_edge",
        change_events=(
            {"offset": -2, "device_role": "firewall", "action": "Enable new outbound NAT policy for partner subnet", "actor": "secops.firewall"},
        ),
        log_events=(
            {"offset": 1, "source_role": "firewall", "event_type": "new_nat_policy_hit", "severity": "info", "message": "New NAT policy receives traffic from 10.20.40.0/24", "role": "root_cause_candidate"},
            {"offset": 3, "source_role": "firewall", "event_type": "session_spike", "severity": "critical", "message": "Session creation rate exceeds normal baseline", "role": "evidence"},
            {"offset": 4, "source_role": "firewall", "event_type": "session_table_near_full", "severity": "critical", "message": "Session table utilization reaches 98 percent", "role": "evidence"},
            {"offset": 5, "source_role": "firewall", "event_type": "cpu_saturation", "severity": "critical", "message": "Firewall CPU high in session worker process", "role": "symptom"},
            {"offset": 8, "source_role": "internet_edge", "event_type": "user_impact", "severity": "critical", "message": "Users report slow internet and failed outbound sessions", "role": "impact"},
        ),
        noise_events=(
            {"offset": 2, "source_role": "dns_server", "event_type": "cache_refresh", "severity": "info", "message": "DNS cache refresh completed"},
        ),
        metric_series=(
            {"offset": -4, "source_role": "firewall", "metric": "session_utilization", "value": 43, "threshold": 85, "unit": "%", "phase": "before"},
            {"offset": 4, "source_role": "firewall", "metric": "session_utilization", "value": 98, "threshold": 85, "unit": "%", "phase": "during"},
            {"offset": 15, "source_role": "firewall", "metric": "session_utilization", "value": 68, "threshold": 85, "unit": "%", "phase": "after"},
            {"offset": -4, "source_role": "firewall", "metric": "cpu_usage", "value": 38, "threshold": 85, "unit": "%", "phase": "before"},
            {"offset": 5, "source_role": "firewall", "metric": "cpu_usage", "value": 94, "threshold": 85, "unit": "%", "phase": "during"},
            {"offset": 16, "source_role": "firewall", "metric": "cpu_usage", "value": 61, "threshold": 85, "unit": "%", "phase": "after"},
        ),
        baseline={"session_utilization": 43, "cpu_usage": 38, "session_setup_rate": "normal"},
        signatures=("fortigate", "session_spike", "session_table", "new_nat_policy_hit", "cpu_saturation", "nat policy"),
        symptoms=("Session table near full", "Firewall CPU high", "Slow outbound sessions"),
        missing_data=("Top session sources and destinations", "Policy hit count by source during spike"),
        verification_steps=("Check top session creators on FortiGate", "Confirm new NAT policy hit count aligns with the incident window", "Validate legitimate traffic after rate limiting"),
        immediate_actions=("Identify top session sources before blocking", "Apply temporary rate limit only to confirmed abusive flows", "Prepare rollback of the NAT policy if it matches the spike"),
        long_term_prevention=("Add per-policy session monitoring", "Capacity-plan firewall session table growth"),
    ),
    IncidentTemplate(
        key="dns-server-timeout",
        category="network",
        root_cause="DNS server timeout",
        severity="major",
        alert_message="DNS timeout and SERVFAIL spike",
        summary="DNS forwarder reachability changes are followed by query latency, timeout, and SERVFAIL spikes.",
        impact="Applications and users fail to resolve external names.",
        topology_role="dns_server",
        impacted_service="name_resolution",
        change_events=(
            {"offset": -3, "device_role": "dns_server", "action": "Update upstream DNS forwarder list", "actor": "sysops.dns"},
        ),
        log_events=(
            {"offset": 0, "source_role": "dns_server", "event_type": "forwarder_unreachable", "severity": "warning", "message": "Primary upstream DNS forwarder is unreachable", "role": "root_cause_candidate"},
            {"offset": 3, "source_role": "dns_server", "event_type": "dns_timeout", "severity": "major", "message": "Recursive query timeout rate increases", "role": "evidence"},
            {"offset": 4, "source_role": "dns_server", "event_type": "servfail_spike", "severity": "major", "message": "SERVFAIL responses exceed threshold", "role": "evidence"},
            {"offset": 6, "source_role": "name_resolution", "event_type": "application_resolution_failure", "severity": "major", "message": "Applications report name resolution failures", "role": "impact"},
        ),
        noise_events=(
            {"offset": 1, "source_role": "core_switch", "event_type": "lldp_neighbor_refresh", "severity": "info", "message": "LLDP neighbor table refreshed"},
        ),
        metric_series=(
            {"offset": -5, "source_role": "dns_server", "metric": "query_latency_ms", "value": 28, "threshold": 500, "unit": "ms", "phase": "before"},
            {"offset": 4, "source_role": "dns_server", "metric": "query_latency_ms", "value": 4200, "threshold": 500, "unit": "ms", "phase": "during"},
            {"offset": 14, "source_role": "dns_server", "metric": "query_latency_ms", "value": 110, "threshold": 500, "unit": "ms", "phase": "after"},
            {"offset": -5, "source_role": "dns_server", "metric": "dns_error_rate", "value": 1, "threshold": 10, "unit": "%", "phase": "before"},
            {"offset": 5, "source_role": "dns_server", "metric": "dns_error_rate", "value": 74, "threshold": 10, "unit": "%", "phase": "during"},
            {"offset": 15, "source_role": "dns_server", "metric": "dns_error_rate", "value": 4, "threshold": 10, "unit": "%", "phase": "after"},
        ),
        baseline={"query_latency_ms": 28, "dns_error_rate": 1},
        signatures=("dns", "dns_timeout", "servfail", "forwarder_unreachable", "query_latency", "upstream dns"),
        symptoms=("DNS timeout", "SERVFAIL spike", "High query latency"),
        missing_data=("Reachability to each configured upstream forwarder", "Representative failing DNS records"),
        verification_steps=("Resolve internal and external records through DNS-HQ-01", "Ping or trace each upstream forwarder", "Confirm SERVFAIL rate returns to baseline"),
        immediate_actions=("Fail clients over to secondary DNS if available", "Restore previous forwarder configuration after verification"),
        long_term_prevention=("Health-check DNS forwarders before changes", "Add synthetic DNS probes"),
    ),
    IncidentTemplate(
        key="linux-disk-full",
        category="system",
        root_cause="Linux server disk full",
        severity="critical",
        alert_message="Linux filesystem nearly full",
        summary="Verbose logging causes fast log directory growth and the application starts failing writes due to no space left.",
        impact="Application transactions fail when they need to write to disk.",
        topology_role="linux_server",
        impacted_service="application",
        change_events=(
            {"offset": -5, "device_role": "linux_server", "action": "Enable debug logging for application troubleshooting", "actor": "appops.linux"},
        ),
        log_events=(
            {"offset": 1, "source_role": "linux_server", "event_type": "log_growth_spike", "severity": "warning", "message": "/var/log/app grows 38 GB in 10 minutes", "role": "root_cause_candidate"},
            {"offset": 3, "source_role": "linux_server", "event_type": "disk_space_low", "severity": "critical", "message": "/var reaches 99 percent usage", "role": "evidence"},
            {"offset": 4, "source_role": "linux_server", "event_type": "write_failed_no_space", "severity": "critical", "message": "Application write failed with ENOSPC", "role": "evidence"},
            {"offset": 7, "source_role": "application", "event_type": "service_degraded", "severity": "critical", "message": "Application API returns 500 on write path", "role": "impact"},
        ),
        noise_events=(
            {"offset": -1, "source_role": "firewall", "event_type": "policy_lookup", "severity": "info", "message": "Firewall policy lookup normal for APP-LNX-01"},
        ),
        metric_series=(
            {"offset": -6, "source_role": "linux_server", "metric": "disk_usage", "value": 71, "threshold": 85, "unit": "%", "phase": "before"},
            {"offset": 4, "source_role": "linux_server", "metric": "disk_usage", "value": 99, "threshold": 85, "unit": "%", "phase": "during"},
            {"offset": 18, "source_role": "linux_server", "metric": "disk_usage", "value": 82, "threshold": 85, "unit": "%", "phase": "after"},
            {"offset": -6, "source_role": "linux_server", "metric": "log_dir_growth_gb", "value": 1, "threshold": 10, "unit": "GB", "phase": "before"},
            {"offset": 3, "source_role": "linux_server", "metric": "log_dir_growth_gb", "value": 38, "threshold": 10, "unit": "GB", "phase": "during"},
            {"offset": 18, "source_role": "linux_server", "metric": "log_dir_growth_gb", "value": 3, "threshold": 10, "unit": "GB", "phase": "after"},
        ),
        baseline={"disk_usage": 71, "log_dir_growth_gb": 1},
        signatures=("disk", "disk_space_low", "no space", "enospc", "log_growth_spike", "debug logging"),
        symptoms=("Filesystem full", "Write failures", "Fast log growth"),
        missing_data=("Largest files and directories on affected filesystem", "Log retention policy currently active"),
        verification_steps=("Run disk usage checks on /var", "Confirm application writes succeed after freeing space", "Verify debug logging is disabled or rate-limited"),
        immediate_actions=("Free or rotate non-essential logs after preserving required evidence", "Disable excessive debug logging after approval"),
        long_term_prevention=("Set log retention and rotation limits", "Add disk growth forecasting alerts"),
    ),
    IncidentTemplate(
        key="windows-service-crash",
        category="system",
        root_cause="Windows service crash",
        severity="critical",
        alert_message="Windows service stopped unexpectedly",
        summary="A dependency update is followed by service exception events, crash loop, and failed health checks on the Windows application host.",
        impact="Users cannot access the Windows-hosted business application.",
        topology_role="windows_server",
        impacted_service="windows_application",
        change_events=(
            {"offset": -4, "device_role": "windows_server", "action": "Deploy new .NET dependency package", "actor": "appops.windows"},
        ),
        log_events=(
            {"offset": 1, "source_role": "windows_server", "event_type": "dependency_error", "severity": "error", "message": "Application event log shows missing method in updated dependency", "role": "root_cause_candidate"},
            {"offset": 2, "source_role": "windows_server", "event_type": "service_crash", "severity": "critical", "message": "Windows service AppGateway terminated unexpectedly", "role": "evidence"},
            {"offset": 4, "source_role": "windows_server", "event_type": "restart_loop", "severity": "critical", "message": "Service Control Manager restarts service repeatedly", "role": "evidence"},
            {"offset": 7, "source_role": "windows_application", "event_type": "health_check_failed", "severity": "critical", "message": "Load balancer marks WIN-APP-01 unhealthy", "role": "impact"},
        ),
        noise_events=(
            {"offset": 5, "source_role": "core_switch", "event_type": "interface_counter_poll", "severity": "info", "message": "Interface counter poll completed"},
        ),
        metric_series=(
            {"offset": -5, "source_role": "windows_server", "metric": "service_availability", "value": 1, "threshold": 1, "unit": "state", "phase": "before"},
            {"offset": 3, "source_role": "windows_server", "metric": "service_availability", "value": 0, "threshold": 1, "unit": "state", "phase": "during"},
            {"offset": 16, "source_role": "windows_server", "metric": "service_availability", "value": 1, "threshold": 1, "unit": "state", "phase": "after"},
            {"offset": -5, "source_role": "windows_server", "metric": "restart_count", "value": 0, "threshold": 2, "unit": "restarts", "phase": "before"},
            {"offset": 5, "source_role": "windows_server", "metric": "restart_count", "value": 12, "threshold": 2, "unit": "restarts", "phase": "during"},
            {"offset": 16, "source_role": "windows_server", "metric": "restart_count", "value": 1, "threshold": 2, "unit": "restarts", "phase": "after"},
        ),
        baseline={"service_availability": 1, "restart_count": 0},
        signatures=("windows", "service_crash", "restart_loop", "dependency_error", "service control manager", ".net dependency"),
        symptoms=("Service crash", "Restart loop", "Health check failed"),
        missing_data=("Exact Windows event IDs around the crash", "Dependency version diff"),
        verification_steps=("Review Windows Application and System event logs", "Confirm service stays running after rollback", "Exercise health endpoint and failed user workflow"),
        immediate_actions=("Rollback the dependency package if it aligns with the crash window", "Start service only after collecting crash evidence"),
        long_term_prevention=("Pin dependency versions", "Add deployment smoke tests for service startup"),
    ),
    IncidentTemplate(
        key="vmware-datastore-full",
        category="system",
        root_cause="VMware datastore full",
        severity="critical",
        alert_message="VMware datastore capacity exhausted",
        summary="A large snapshot grows rapidly, datastore free space drops below threshold, and VMs report stun or IO latency.",
        impact="Virtual machines on the datastore experience IO stalls and application latency.",
        topology_role="vmware_datastore",
        impacted_service="virtualization",
        change_events=(
            {"offset": -6, "device_role": "vmware_cluster", "action": "Create snapshot for DB-01 before maintenance", "actor": "virt.admin"},
        ),
        log_events=(
            {"offset": 1, "source_role": "vmware_cluster", "event_type": "snapshot_growth", "severity": "warning", "message": "DB-01 snapshot grows rapidly after maintenance window starts", "role": "root_cause_candidate"},
            {"offset": 3, "source_role": "vmware_datastore", "event_type": "datastore_low_space", "severity": "critical", "message": "DS-PRD-01 free space below 1 percent", "role": "evidence"},
            {"offset": 5, "source_role": "vmware_cluster", "event_type": "vm_stun", "severity": "critical", "message": "VMware reports VM stun on DB-01", "role": "impact"},
            {"offset": 8, "source_role": "virtualization", "event_type": "io_latency_high", "severity": "critical", "message": "VM IO latency high on datastore DS-PRD-01", "role": "symptom"},
        ),
        noise_events=(
            {"offset": -2, "source_role": "dns_server", "event_type": "dns_query_normal", "severity": "info", "message": "DNS query latency remains normal"},
        ),
        metric_series=(
            {"offset": -8, "source_role": "vmware_datastore", "metric": "datastore_usage", "value": 72, "threshold": 85, "unit": "%", "phase": "before"},
            {"offset": 4, "source_role": "vmware_datastore", "metric": "datastore_usage", "value": 99, "threshold": 85, "unit": "%", "phase": "during"},
            {"offset": 20, "source_role": "vmware_datastore", "metric": "datastore_usage", "value": 81, "threshold": 85, "unit": "%", "phase": "after"},
            {"offset": -8, "source_role": "vmware_cluster", "metric": "snapshot_size_gb", "value": 20, "threshold": 100, "unit": "GB", "phase": "before"},
            {"offset": 3, "source_role": "vmware_cluster", "metric": "snapshot_size_gb", "value": 640, "threshold": 100, "unit": "GB", "phase": "during"},
            {"offset": 20, "source_role": "vmware_cluster", "metric": "snapshot_size_gb", "value": 45, "threshold": 100, "unit": "GB", "phase": "after"},
        ),
        baseline={"datastore_usage": 72, "snapshot_size_gb": 20},
        signatures=("vmware", "datastore", "snapshot_growth", "datastore_low_space", "vm_stun", "snapshot"),
        symptoms=("Datastore full", "Snapshot growth", "VM stun", "High IO latency"),
        missing_data=("Snapshot owner and retention reason", "Datastore free space by VM"),
        verification_steps=("List snapshots on VMs in DS-PRD-01", "Confirm datastore free space and VM IO latency after consolidation", "Check for other thin-provisioning growth"),
        immediate_actions=("Consolidate or remove unnecessary snapshots after owner approval", "Migrate or extend datastore capacity if consolidation is unsafe"),
        long_term_prevention=("Enforce snapshot age and size policy", "Alert on fast datastore growth"),
    ),
    IncidentTemplate(
        key="interface-flapping",
        category="network",
        root_cause="Interface flapping",
        severity="major",
        alert_message="Interface flapping detected on uplink",
        summary="An uplink repeatedly transitions down/up with CRC errors, causing LACP member instability and traffic loss.",
        impact="Branch or access segment connectivity is unstable.",
        topology_role="access_switch",
        impacted_service="branch_connectivity",
        change_events=(
            {"offset": -2, "device_role": "access_switch", "action": "Replace patch cable on uplink ge-0/0/1", "actor": "field.engineer"},
        ),
        log_events=(
            {"offset": 1, "source_role": "access_switch", "event_type": "link_down", "severity": "warning", "message": "ge-0/0/1 link down", "role": "evidence"},
            {"offset": 2, "source_role": "access_switch", "event_type": "link_up", "severity": "warning", "message": "ge-0/0/1 link up after 14 seconds", "role": "evidence"},
            {"offset": 4, "source_role": "access_switch", "event_type": "crc_errors", "severity": "major", "message": "CRC errors increase on ge-0/0/1", "role": "root_cause_candidate"},
            {"offset": 5, "source_role": "core_switch", "event_type": "lacp_member_removed", "severity": "major", "message": "LACP removes ge-0/0/1 from bundle due to link instability", "role": "symptom"},
            {"offset": 9, "source_role": "branch_connectivity", "event_type": "user_impact", "severity": "major", "message": "Users report intermittent connectivity", "role": "impact"},
        ),
        noise_events=(
            {"offset": 3, "source_role": "windows_server", "event_type": "patch_scan_complete", "severity": "info", "message": "Patch scan completed with no pending reboot"},
        ),
        metric_series=(
            {"offset": -3, "source_role": "access_switch", "metric": "interface_flap_count", "value": 0, "threshold": 3, "unit": "flaps", "phase": "before"},
            {"offset": 5, "source_role": "access_switch", "metric": "interface_flap_count", "value": 18, "threshold": 3, "unit": "flaps", "phase": "during"},
            {"offset": 18, "source_role": "access_switch", "metric": "interface_flap_count", "value": 0, "threshold": 3, "unit": "flaps", "phase": "after"},
            {"offset": -3, "source_role": "access_switch", "metric": "crc_error_rate", "value": 3, "threshold": 100, "unit": "errors/min", "phase": "before"},
            {"offset": 6, "source_role": "access_switch", "metric": "crc_error_rate", "value": 2200, "threshold": 100, "unit": "errors/min", "phase": "during"},
            {"offset": 18, "source_role": "access_switch", "metric": "crc_error_rate", "value": 12, "threshold": 100, "unit": "errors/min", "phase": "after"},
        ),
        baseline={"interface_flap_count": 0, "crc_error_rate": 3},
        signatures=("interface", "flapping", "link_down", "link_up", "crc_errors", "lacp_member_removed", "ge-0/0/1"),
        symptoms=("Link up/down", "CRC error spike", "LACP member removal"),
        missing_data=("Physical cable and optic condition", "Peer interface counters"),
        verification_steps=("Check both ends of ge-0/0/1 for errors", "Confirm flap count remains zero for 15 minutes", "Swap cable or optic only after evidence collection"),
        immediate_actions=("Move traffic to a stable uplink if available", "Inspect cable, optic, and switchport errors"),
        long_term_prevention=("Replace suspect physical media", "Alert on repeated link state changes plus CRC errors"),
    ),
    IncidentTemplate(
        key="routing-issue",
        category="network",
        root_cause="Routing issue",
        severity="major",
        alert_message="Route withdrawal causing reachability loss",
        summary="A prefix filter change is followed by route withdrawal, next-hop unreachable events, and packet loss to remote networks.",
        impact="Remote branch or partner routes become unreachable.",
        topology_role="edge_router",
        impacted_service="wan",
        change_events=(
            {"offset": -2, "device_role": "edge_router", "action": "Update BGP outbound prefix filter", "actor": "netops.routing"},
        ),
        log_events=(
            {"offset": 0, "source_role": "edge_router", "event_type": "prefix_denied", "severity": "warning", "message": "Expected partner prefix denied by new policy", "role": "root_cause_candidate"},
            {"offset": 2, "source_role": "edge_router", "event_type": "route_withdrawal", "severity": "major", "message": "BGP withdraws 172.30.40.0/24 from routing table", "role": "evidence"},
            {"offset": 3, "source_role": "edge_router", "event_type": "next_hop_unreachable", "severity": "major", "message": "Next-hop unreachable for partner route", "role": "evidence"},
            {"offset": 7, "source_role": "wan", "event_type": "reachability_loss", "severity": "major", "message": "Synthetic probe to partner network fails", "role": "impact"},
        ),
        noise_events=(
            {"offset": 2, "source_role": "linux_server", "event_type": "cron_job_started", "severity": "info", "message": "Local cleanup cron started"},
        ),
        metric_series=(
            {"offset": -4, "source_role": "edge_router", "metric": "route_count", "value": 410, "threshold": 350, "unit": "routes", "phase": "before"},
            {"offset": 3, "source_role": "edge_router", "metric": "route_count", "value": 118, "threshold": 350, "unit": "routes", "phase": "during"},
            {"offset": 17, "source_role": "edge_router", "metric": "route_count", "value": 405, "threshold": 350, "unit": "routes", "phase": "after"},
            {"offset": -4, "source_role": "edge_router", "metric": "packet_loss", "value": 0, "threshold": 5, "unit": "%", "phase": "before"},
            {"offset": 7, "source_role": "edge_router", "metric": "packet_loss", "value": 31, "threshold": 5, "unit": "%", "phase": "during"},
            {"offset": 17, "source_role": "edge_router", "metric": "packet_loss", "value": 1, "threshold": 5, "unit": "%", "phase": "after"},
        ),
        baseline={"route_count": 410, "packet_loss": 0},
        signatures=("routing", "bgp", "prefix_denied", "route_withdrawal", "next_hop_unreachable", "prefix filter"),
        symptoms=("Route count drop", "Route withdrawal", "Packet loss"),
        missing_data=("Expected route policy diff", "BGP neighbor state and advertised routes"),
        verification_steps=("Check BGP neighbor state and prefix filters", "Confirm expected prefixes are installed", "Run reachability tests from affected segments"),
        immediate_actions=("Rollback prefix filter if it matches the outage window", "Avoid clearing all sessions unless verified necessary"),
        long_term_prevention=("Peer-review route policy changes", "Add route-count anomaly alerts"),
    ),
    IncidentTemplate(
        key="brute-force-wazuh",
        category="security",
        root_cause="Brute force attack detected by Wazuh",
        severity="critical",
        alert_message="Wazuh detects brute force authentication pattern",
        summary="Wazuh correlates failed login spikes, account lockouts, and a single source attempting many users.",
        impact="Identity service is under attack and targeted accounts may be locked.",
        topology_role="wazuh",
        impacted_service="identity",
        change_events=(
            {"offset": -10, "device_role": "firewall", "action": "Open VPN portal to new partner IP range", "actor": "secops.vpn"},
        ),
        log_events=(
            {"offset": 1, "source_role": "wazuh", "event_type": "failed_login_spike", "severity": "critical", "message": "Wazuh rule 5710 triggers on SSH/VPN failed login spike", "role": "evidence"},
            {"offset": 2, "source_role": "identity_server", "event_type": "same_source_many_users", "severity": "critical", "message": "Source 203.0.113.88 attempts logins for 74 users", "role": "root_cause_candidate"},
            {"offset": 4, "source_role": "identity_server", "event_type": "account_lockout", "severity": "major", "message": "Multiple user accounts locked after repeated failures", "role": "impact"},
            {"offset": 6, "source_role": "firewall", "event_type": "vpn_auth_failure", "severity": "critical", "message": "VPN authentication failures exceed threshold from 203.0.113.88", "role": "evidence"},
        ),
        noise_events=(
            {"offset": 3, "source_role": "vmware_cluster", "event_type": "vm_snapshot_check", "severity": "info", "message": "VM snapshot check completed"},
        ),
        metric_series=(
            {"offset": -4, "source_role": "wazuh", "metric": "failed_login_rate", "value": 18, "threshold": 200, "unit": "events/min", "phase": "before"},
            {"offset": 2, "source_role": "wazuh", "metric": "failed_login_rate", "value": 2400, "threshold": 200, "unit": "events/min", "phase": "during"},
            {"offset": 20, "source_role": "wazuh", "metric": "failed_login_rate", "value": 60, "threshold": 200, "unit": "events/min", "phase": "after"},
            {"offset": -4, "source_role": "identity_server", "metric": "lockout_count", "value": 1, "threshold": 10, "unit": "accounts", "phase": "before"},
            {"offset": 5, "source_role": "identity_server", "metric": "lockout_count", "value": 80, "threshold": 10, "unit": "accounts", "phase": "during"},
            {"offset": 20, "source_role": "identity_server", "metric": "lockout_count", "value": 4, "threshold": 10, "unit": "accounts", "phase": "after"},
        ),
        baseline={"failed_login_rate": 18, "lockout_count": 1},
        signatures=("wazuh", "brute force", "failed_login_spike", "same_source_many_users", "account_lockout", "vpn_auth_failure"),
        symptoms=("Failed login spike", "Same source targets many users", "Account lockouts"),
        missing_data=("Successful logins from the attacking source", "Asset owner approval before blocking partner range"),
        verification_steps=("Review successful logins during the attack window", "Confirm the source IP is not an approved scanner", "Check whether MFA challenged the attempts"),
        immediate_actions=("Rate-limit or block the abusive source after ownership check", "Protect targeted accounts and review successful logins"),
        long_term_prevention=("Add adaptive lockout and geo-risk controls", "Tune Wazuh rules for VPN authentication bursts"),
    ),
)


TEMPLATES_BY_KEY = {template.key: template for template in TEMPLATES}
TEMPLATES_BY_ROOT_CAUSE = {template.root_cause: template for template in TEMPLATES}
CATEGORIES = tuple(sorted({template.category for template in TEMPLATES}))
REQUIRED_SCENARIO_KEYS = tuple(template.key for template in TEMPLATES)
