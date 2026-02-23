# CloudAudit

**Next-Generation AI-Powered Cloud Security Auditing Framework**

```
                                                                                              
              ,,                           ,,                                ,,    ,,         
  .g8"""bgd `7MM                         `7MM        db                    `7MM    db   mm    
.dP'     `M   MM                           MM       ;MM:                     MM         MM    
dM'       `   MM  ,pW"Wq.`7MM  `7MM   ,M""bMM      ,V^MM.  `7MM  `7MM   ,M""bMM  `7MM mmMMmm  
MM            MM 6W'   `Wb MM    MM ,AP    MM     ,M  `MM    MM    MM ,AP    MM    MM   MM    
MM.           MM 8M     M8 MM    MM 8MI    MM     AbmmmqMA   MM    MM 8MI    MM    MM   MM    
`Mb.     ,'   MM YA.   ,A9 MM    MM `Mb    MM    A'     VML  MM    MM `Mb    MM    MM   MM    
  `"bmmmd'  .JMML.`Ybmd9'  `Mbod"YML.`Wbmd"MML..AMA.   .AMMA.`Mbod"YML.`Wbmd"MML..JMML. `Mbmo 
         
```

[![Version](https://img.shields.io/badge/version-1.0.2-blue)](#)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](#)
[![Mode](https://img.shields.io/badge/mode-read--only-green)](#)
[![Docs](https://img.shields.io/readthedocs/cloudaudit)](#)
[![License](https://img.shields.io/badge/license-Proprietary-red)](#)

> **Developed by xtawb** | [https://linktr.ee/xtawb](https://linktr.ee/xtawb)

---

CloudAudit is an enterprise-grade cloud storage security posture auditing
framework. It discovers, crawls, and analyses publicly exposed cloud storage
containers — AWS S3, Google Cloud Storage, Azure Blob Storage, open directory
listings — to identify secret leakage, credential exposure, compliance gaps,
and misconfigurations before attackers do.

## Quick Start

```bash
pip install -e ".[gemini]"

cloudaudit -u https://mybucket.s3.amazonaws.com/ \
           --confirm-ownership \
           --org-name "Acme Corp" \
           --provider gemini
```

## Design Philosophy

- **Read-only by architecture** — only GET, HEAD, OPTIONS exist in the HTTP client
- **Ownership-gated** — requires explicit `--confirm-ownership` flag
- **Secrets never stored raw** — all matches are redacted before write or transmission
- **No exploitation guidance** — AI providers are prompted for defensive output only

Navigate the documentation using the tabs above.
