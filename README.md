# EDRChoker

EDRChoker uses **Policy-based Quality of Service (QoS)** to set hard bandwidth caps (throttling) on Endpoint Detection and Response (EDR) agents, causing them to always time out - effectively blocking them. 

**The rules take effect immediately and persist after the target reboots Windows.**

EDRChoker relies on Windows' **pacer.sys** driver.

### Command Line Syntax

**EDRChoker.exe `<ListFile`>**

_To create QoS Policy for all process name in ListFile - Each line per process_

**EDRChoker.exe**

_To remove all installed QoS Policy_

## Links

[EDRChoker: Choking The Telemetry Stream to Bypass Defenses](https://www.zerosalarium.com/2026/06/edrchoker-choking-telemetry-stream-block-edr.html)

### Some EDR/Antivirus have been successfully tested

- **Elastic Defend**
- ...
- _Please contact me if you successfully test it against any other EDR._

## Demo Video

Youtube EDR-Redir V1: [https://www.youtube.com/watch?v=2_tanx7RSUw](https://www.youtube.com/watch?v=2_tanx7RSUw)


## 🐦 Enjoying my work? Support the journey by following me on X

[![Twitter Follow](https://img.shields.io/twitter/follow/TwoSevenOneT?style=for-the-badge&logo=x&color=000)](https://x.com/TwoSevenOneT)

## Author:

[Two Seven One Three](https://x.com/TwoSevenOneT)
