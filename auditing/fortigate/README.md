# FortiGate Policy Viewer

This project is a lightweight browser-based viewer for FortiGate configuration files. It focuses on turning `config firewall policy` sections into a readable table and enriching those rules with details parsed from related objects such as addresses, address groups, VIPs, services, interfaces, and security profiles.

The viewer is implemented as a single static HTML file: `fortigate-viewer.html`. There is no build step, backend, or dependency installation required.

## Features

- Load a local FortiGate configuration export directly in the browser.
- Display firewall policies in a table with these columns:
  - Policy
  - From
  - To
  - Source
  - Destination
  - Schedule
  - Service
  - Action
  - NAT
  - Security Profiles
  - Log
- Hover badges to inspect additional details for:
  - Interfaces
  - Address objects
  - Geography objects
  - VIPs
  - Custom services
- Click `From` or `To` badges to filter the table by interface.
- Use `Reset Filters` to return to the full policy list.
- Highlight potentially shadowed rules with a light red background.

## Parsed Data

The current viewer understands these FortiGate object types and fields:

- `config firewall policy`
- `config firewall address`
  - IPv4 subnet objects
  - geography objects via `set type geography` and `set country`
- `config firewall addrgrp`
- `config firewall vip`
- `config firewall service custom`
- `config system interface`

For security profiles, the viewer reads common policy keys such as:

- `ssl-ssh-profile`
- `application-list`
- `av-profile`
- `ips-sensor`
- `webfilter-profile`
- `dnsfilter-profile`
- `spamfilter-profile`
- `dlp-sensor`
- `waf-profile`
- `file-filter-profile`
- `icap-profile`
- `profile-protocol-options`
- `voip-profile`
- `videofilter-profile`
- `casb-profile`
- `profile-group`

It also picks up additional profile bindings when the setting name ends with `-profile` or `-sensor`.

## Limitations

This is intentionally a quick analysis tool, not a full FortiGate parser.

- It does not fully model every FortiGate configuration section or every syntax variation.
- Shadow-rule detection is basic and should be treated as a hint, not a definitive result.
- Nested object resolution is partial.
- The viewer currently targets IPv4-style policy exports and common object layouts.

## Usage

1. Open `fortigate-viewer.html` in your browser.
2. Click the file picker and select a FortiGate configuration export.
3. Review the rendered policy table.
4. Hover badges to inspect object details.
5. Click a `From` or `To` badge to filter the rules.
6. Click `Reset Filters` to clear the active filters.

## Sample Config

A sample configuration is included for testing:

- `sample-fortigate-config.conf`

This sample contains:

- interface definitions with IPs and VLANs
- subnet and geography address objects
- address groups
- custom services
- a VIP
- several example policies
- attached security profiles

## Project Files

- `fortigate-viewer.html` - the viewer UI and parser
- `README.md` - project overview and usage
- `sample-fortigate-config.conf` - sample FortiGate config for testing
