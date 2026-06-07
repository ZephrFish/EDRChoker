# EDRChoker BOF

Beacon Object File port of [EDRChoker](https://github.com/TwoSevenOneT/EDRChoker). Throttles EDR/AV process network to 8 bytes/sec in-process via WMI QoS policy, result being no child process, no powershell, no netsh.

Only caveat being that you need to be in an elevated process for this to work.

## How it works

Creates `MSFT_NetQosPolicySettingData` instances in `ROOT\StandardCimv2` via COM/WMI. The policy applies immediately to the active store and matches by application path name. The result is the target process network is throttled to effectively zero throughput, preventing telemetry reaching the vendor cloud while leaving the process running.

Cleanup mode queries `Owner = 1` (user-created) policies and deletes them.

## Requirements

- Elevated Beacon (local admin or SYSTEM)
- Windows 8 / Server 2012 or later (`MSFT_NetQosPolicySettingData` does not exist on Win7/2008)
- QoS Packet Scheduler enabled on the target network adapter
- **Compile**: `mingw-w64 >= 5.0` (`brew install mingw-w64` / `apt install mingw-w64`)

## Build

```sh
cd bof/
make          # builds both edrchoker.o (x64) and edrchoker.x86.o (x86)
```

## Usage (Cobalt Strike)

Load `edrchoker.cna` via Script Manager. The script auto-selects the correct arch object file based on the beacon.

```
# Throttle one or more processes
edrchoker MsSense.exe
edrchoker MsSense.exe SentinelAgent.exe cb.exe

# Remove all user QoS policies (cleanup)
edrchoker
```

## Notes

- Policies are tagged `Owner = 1` so cleanup is surgical; system QoS defaults are untouched
- Policies survive reboot; run `edrchoker` (no args) to clean up before ending the engagement
- WMI activity is logged to `Microsoft-Windows-WMI-Activity/Operational` - account for this in your OPSEC planning
- Some EDR products route telemetry via kernel-mode miniport drivers that sit below the QoS layer; validate against your specific target before relying on this technique
