# SpecterBroker
Advanced Windows authentication token extraction and decryption tool for red team operations and security research

```
═══════════════════════════════════════════════════════════════
 ▓▒░ 01010011 01010000 01000101 01000011 01010100 01000101 01010010 ░▒▓
═══════════════════════════════════════════════════════════════

  ███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗ 
  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
  ███████╗██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝
  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗
  ███████║██║     ███████╗╚██████╗   ██║   ███████╗██║  ██║
  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

  ██████╗ ██████╗  ██████╗ ██╗  ██╗███████╗██████╗ 
  ██╔══██╗██╔══██╗██╔═══██╗██║ ██╔╝██╔════╝██╔══██╗
  ██████╔╝██████╔╝██║   ██║█████╔╝ █████╗  ██████╔╝
  ██╔══██╗██╔══██╗██║   ██║██╔═██╗ ██╔══╝  ██╔══██╗
  ██████╔╝██║  ██║╚██████╔╝██║  ██╗███████╗██║  ██║
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

  Windows Auth Token Decryptor v1.1
  DPAPI | TBRes | WAM | NGC | FOCI

═══════════════════════════════════════════════════════════════
```

**Advanced Windows authentication token extraction and decryption tool for red team operations and security research.**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)]()
[![.NET](https://img.shields.io/badge/.NET-Framework%204.8-512BD4.svg)]()
[![Language](https://img.shields.io/badge/language-C%23-239120.svg)]()

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Disclaimer](#disclaimer)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Output Format](#output-format)
- [Technical Details](#technical-details)
- [Detection & OPSEC](#detection--opsec)
- [Credits](#credits)
- [License](#license)

---

## 🎯 Overview

**SpecterBroker** is a comprehensive post-exploitation tool designed for extracting and decrypting Windows authentication tokens from multiple sources. It targets the Windows Authentication Manager (WAM), Token Broker cache (TBRes), and related authentication subsystems to retrieve Access Tokens, Refresh Tokens, ID Tokens, and NGC (Next Generation Credentials) tokens.

This tool is specifically designed for:
- **Red Team Operations**: Token extraction during authorized penetration testing
- **Security Research**: Understanding Windows authentication mechanisms
- **DFIR Analysis**: Forensic investigation of authentication artifacts
- **Educational Purposes**: Learning about Windows credential storage

### What Makes It Special?

- **Unified Extraction**: Combines multiple token extraction techniques in a single tool
- **DPAPI Decryption**: Automatic decryption of protected token caches using Windows DPAPI
- **Multiple Formats**: Supports both TBRes and WAM cache formats
- **FOCI Detection**: Identifies Family of Client IDs (FOCI) enabled tokens
- **Metadata Extraction**: Retrieves UPN, tenant ID, client ID, scopes, and expiration data
- **Office Master Tokens**: Detects high-value Office 365 master tokens

---

## ✨ Features

### Core Capabilities

- ✅ **TBRes Cache Extraction** - Decrypts `.tbres` files from TokenBroker cache
- ✅ **WAM Cache Extraction** - Processes AAD BrokerPlugin cached authentication data
- ✅ **DPAPI Decryption** - Leverages Windows DPAPI for automatic token decryption
- ✅ **JWT Parsing** - Extracts and parses JSON Web Tokens (Access & ID tokens)
- ✅ **Refresh Token Extraction** - Retrieves Microsoft v1 Refresh Tokens (1.AV0A format)
- ✅ **NGC Token Support** - Extracts Next Generation Credentials tokens
- ✅ **FOCI Detection** - Identifies Family of Client IDs enabled applications
- ✅ **Metadata Enrichment** - Extracts UPN, tenant ID, client ID, scopes, expiration

### Advanced Features

- 🔍 **Automatic Deduplication** - Intelligent token deduplication across cache files
- 📊 **Dual Output Format** - Compatible with both TBRes and BrokerDecrypt formats
- ⏱️ **Expiration Filtering** - Automatically skips expired access tokens
- 🎯 **Office Master Detection** - Flags high-value Office 365 master tokens
- 📁 **Recursive Processing** - Scans entire cache directory structures
- 🔐 **Local Machine Scope** - Operates with current user context (no elevation required)

---

## ⚠️ Disclaimer

**IMPORTANT - READ CAREFULLY**

This tool is provided **for educational and authorized security testing purposes only**. 

### Legal Notice

- ✅ **Authorized Use Only**: Use only on systems you own or have explicit written permission to test
- ❌ **Unauthorized Access**: Using this tool without proper authorization may violate:


### Ethical Guidelines

By using this tool, you agree to:

1. **Only use on authorized systems** during legitimate red team engagements or penetration tests
2. **Obtain proper written authorization** before any security testing
3. **Handle extracted credentials responsibly** and securely delete them after testing
4. **Not use for malicious purposes** including unauthorized access, data theft, or system compromise
5. **Comply with all applicable laws** and regulations in your jurisdiction

### Limitation of Liability

The authors and contributors:
- Provide this tool "AS IS" without warranty of any kind
- Are NOT responsible for any misuse or damage caused by this tool
- Do NOT condone or support any unauthorized or illegal activities
- Assume NO liability for any legal consequences of improper use

**IF YOU DO NOT AGREE WITH THESE TERMS, DO NOT USE THIS TOOL.**

---

## 📦 Prerequisites

### System Requirements

- **Operating System**: Windows 10/11 or Windows Server 2016+
- **.NET Framework**: 4.8 or higher
- **Architecture**: x64 (64-bit)
- **Privileges**: Standard user context (no elevation required)

### Build Requirements

- **MSBuild**: Version 17.0+ (Visual Studio 2022 or Build Tools)
- **NuGet**: For package restoration
- **.NET SDK**: 4.8 targeting pack

### Runtime Dependencies

The following NuGet packages are automatically restored during build:

- `BouncyCastle.Cryptography` v2.6.1 - Cryptographic operations
- `System.Formats.Asn1` v9.0.7 - ASN.1 parsing
- `System.Text.Json` v9.0.7 - JSON serialization
- `Costura.Fody` v5.7.0 - Assembly embedding

---

## 🔧 Installation

### Option 1: Clone and Build

```bash
# Clone repository
git clone https://github.com/r3alm0m1x82/SpecterBroker.git
cd SpecterBroker

# Build using provided script
build.bat

# Binary will be in: bin\Release\net48\SpecterBroker.exe
```

### Option 2: Manual Build

```bash
# Restore packages
msbuild SpecterBroker.csproj /t:Restore

# Build release version
msbuild SpecterBroker.csproj /p:Configuration=Release

# Output: bin\Release\net48\SpecterBroker.exe
```

### Option 3: Visual Studio

1. Open `SpecterBroker.sln` in Visual Studio 2022
2. Select **Release** configuration
3. Build Solution (Ctrl+Shift+B)
4. Binary: `bin\Release\net48\SpecterBroker.exe`

---

## 🚀 Usage

### Basic Execution

Simply run the executable from command line or PowerShell:

```bash
# Run with default settings
SpecterBroker.exe
```

### Execution Flow

The tool automatically:

1. Displays the banner with version information
2. Locates Windows authentication caches:
   - TokenBroker cache: `%LOCALAPPDATA%\Microsoft\TokenBroker\Cache`
   - AAD BrokerPlugin: `%LOCALAPPDATA%\Packages\Microsoft.AAD.BrokerPlugin_*\LocalState`
3. Extracts and decrypts tokens using DPAPI
4. Deduplicates and filters expired tokens
5. Generates two JSON output files with extracted data

### Expected Output

```
═══════════════════════════════════════════════════════════════
 ▓▒░ SPECTER ░▒▓  BROKER
═══════════════════════════════════════════════════════════════

  [+] Windows Auth Token Decryptor v.1.1
  [+] by r3alm0m1x82 - safebreach.it
  [*] DPAPI | TBRes | WAM | NGC | FOCI

[*] Processing cache type 1...
[*] Path: C:\Users\...\TokenBroker\Cache
[+] Found 15 entries from 23 files

[*] Processing cache type 2...
[*] Path: C:\Users\...\AAD.BrokerPlugin_...\LocalState
[+] Found 42 entries from 156 files

═══════════════════════════════════════════════════════════════
[+] TOTAL DATA EXTRACTED:
    Type 1: 15 entries
    Type 2: 42 entries
═══════════════════════════════════════════════════════════════

[*] Type 2 Access Data: 12  <--- ACCESS TOKENS!
[*] Type 2 Refresh Data: 18 <--- REFRESH TOKENS!
[*] Type 2 NGC Data: 12
[*] Type 1 Data: 15
[*] Expired skipped: 8

[+] Type 1 data saved to: cache_export_type1_20241215_143022.json
[+] Type 2 data saved to: cache_export_type2_20241215_143022.json

[*] Done.
```

### Output Files

Two JSON files are generated:

1. **cache_export_type1_YYYYMMDD_HHMMSS.json** - TBRes format tokens
2. **cache_export_type2_YYYYMMDD_HHMMSS.json** - WAM/BrokerDecrypt format tokens

---

## 📊 Output Format

```json
{
  "target": "WORKSTATION01",
  "extraction_time": "2024-12-15T14:30:22Z",
  "working_directory": "C:\\Users\\...",
  "files_processed": 23,
  "tokens_extracted": 15,
  "tokens_skipped_expired": 3,
  "has_office_master_token": true,
  "tokens": [
    {
      "source_file": "12345678-abcd-1234-5678-123456789abc.tbres",
      "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
      "id_token": "eyJ0eXAiOiJKV1QiLCJub25jZSI...",
      "refresh_token": null,
      "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
      "upn": "user@company.com",
      "scope": "Mail.Read Calendars.Read",
      "tenant_id": "12345678-1234-1234-1234-123456789abc",
      "extracted_from": "TBRes Cache",
      "extracted_at": "2024-12-15T14:30:22Z"
    }
  ]
}
```

```json
{
  "metadata": {
    "timestamp": "2024-12-15T14:30:22Z",
    "hostname": "WORKSTATION01",
    "username": "user",
    "extraction_method": "CacheProcessor",
    "target_computer": "WORKSTATION01"
  },
  "tokens": [
    {
      "type": "refresh_token",
      "token": "1.AV0A12345...",
      "email": "user@company.com",
      "tenant_id": "12345678-1234-1234-1234-123456789abc",
      "user_oid": "87654321-4321-4321-4321-210987654321",
      "display_name": "John Doe",
      "cache_path": "C:\\Users\\...\\p_abc123",
      "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
      "login_url": "https://login.microsoftonline.com/12345678-..."
    },
    {
      "type": "access_token",
      "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
      "cache_path": "C:\\Users\\...\\a_xyz789",
      "client_id": "00000003-0000-0000-c000-000000000000",
      "email": "user@company.com",
      "tenant_id": "12345678-1234-1234-1234-123456789abc",
      "user_oid": "87654321-4321-4321-4321-210987654321",
      "display_name": "John Doe",
      "scope": "Mail.Read Calendars.Read Files.ReadWrite",
      "expires_at": "2024-12-15T15:30:22Z",
      "session_key": "abc123...",
      "login_url": "https://login.microsoftonline.com/12345678-..."
    },
    {
      "type": "ngc_token",
      "token": "AQAAAAEAAAABAAAA...",
      "cache_path": "C:\\Users\\...\\n_def456"
    }
  ],
  "statistics": {
    "total_tokens": 42,
    "access_tokens": 12,
    "refresh_tokens": 18,
    "ngc_tokens": 12
  }
}
```

### Token Types Explained

| Type | Description | Use Case |
|------|-------------|----------|
| **Access Token (AT)** | JWT bearer token for API access | Direct API calls to Microsoft Graph, Azure, etc. |
| **Refresh Token (RT)** | Long-lived token for obtaining new ATs | Token refresh without re-authentication |
| **ID Token** | JWT containing user identity claims | User profile information |
| **NGC Token** | Next Generation Credentials token | Windows Hello / passwordless auth |

---

## 🔬 Technical Details

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     SpecterBroker                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐    ┌──────────────┐   ┌──────────────┐    │
│  │   TBRes      │    │     WAM      │   │    DPAPI     │    │
│  │  Extractor   │◄───┤  Extractor   │◄──┤  Decryptor   │    │
│  └──────────────┘    └──────────────┘   └──────────────┘    │
│         │                    │                    │         │
│         └────────────────────┴────────────────────┘         │
│                              ▼                              │
│                    ┌──────────────────┐                     │
│                    │  Token Parser    │                     │
│                    │  & Deduplicator  │                     │
│                    └──────────────────┘                     │
│                              ▼                              │
│                    ┌──────────────────┐                     │
│                    │  JSON Serializer │                     │
│                    └──────────────────┘                     │
│                              ▼                              │
│                    ┌──────────────────┐                     │
│                    │  Output Files    │                     │
│                    └──────────────────┘                     │
└─────────────────────────────────────────────────────────────┘
```

### Extraction Techniques

#### 1. TBRes Cache Extraction

Targets: `%LOCALAPPDATA%\Microsoft\TokenBroker\Cache\*.tbres`

- Reads `.tbres` files (UTF-16LE encoded)
- Locates `ResponseBytes.Value` field containing encrypted payload
- Decrypts using DPAPI (`ProtectedData.Unprotect`)
- Parses JSON structure to extract tokens
- Extracts Access Tokens, ID Tokens, and metadata

#### 2. WAM Cache Extraction

Targets: `%LOCALAPPDATA%\Packages\Microsoft.AAD.BrokerPlugin_*\LocalState\*`

- Processes files: `p_*`, `a_*`, and `*.def`
- Parses ASN.1/CMS EnvelopedData structure
- Extracts KEK (Key Encryption Key) from CNG blob
- Unwraps CEK (Content Encryption Key) using RFC 3394
- Decrypts AES-GCM ciphertext using BouncyCastle
- Decompresses DEFLATE payload
- Extracts all token types: RT, AT, NGC

#### 3. DPAPI Decryption

- Uses Windows DPAPI (`System.Security.Cryptography.ProtectedData`)
- Operates in `CurrentUser` scope (no elevation required)
- Automatically uses user's master key
- Supports both `LocalMachine` and `CurrentUser` scopes

### Cryptographic Operations

```
┌─────────────────────────────────────────────────────────────┐
│  Encrypted TBRes File                                       │
│  ┌────────────────────────────────────────────────────┐     │
│  │  Base64(DPAPI-Protected-Data)                      │     │
│  └────────────────────────────────────────────────────┘     │
│                         │                                    │
│                         ▼                                    │
│  ┌────────────────────────────────────────────────────┐     │
│  │  DPAPI Decrypt (CurrentUser)                       │     │
│  └────────────────────────────────────────────────────┘     │
│                         │                                    │
│                         ▼                                    │
│  ┌────────────────────────────────────────────────────┐     │
│  │  Plaintext JSON (tokens + metadata)                │     │
│  └────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Encrypted WAM Cache File                                   │
│  ┌────────────────────────────────────────────────────┐     │
│  │  ASN.1 CMS EnvelopedData                           │     │
│  │  ├─ KEK (DPAPI-Protected)                          │     │
│  │  ├─ Wrapped CEK (RFC 3394)                         │     │
│  │  └─ AES-GCM Ciphertext + Tag                       │     │
│  └────────────────────────────────────────────────────┘     │
│                         │                                    │
│                         ▼                                    │
│  ┌────────────────────────────────────────────────────┐     │
│  │  1. DPAPI Unwrap KEK                               │     │
│  │  2. RFC 3394 Unwrap CEK                            │     │
│  │  3. AES-GCM Decrypt                                │     │
│  │  4. DEFLATE Decompress                             │     │
│  └────────────────────────────────────────────────────┘     │
│                         │                                    │
│                         ▼                                    │
│  ┌────────────────────────────────────────────────────┐     │
│  │  Plaintext (tokens + metadata)                     │     │
│  └────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### Token Format Recognition

#### Refresh Token (Microsoft v1)

Format: `1.AV0A[TenantID_B64][ClientID_B64][Random]...`

```
1.AV0A xyz123...
  │ │└─ Version marker
  │ └── Random header
  └──── Version prefix

First 44 chars after prefix (Base64URL):
  - Bytes 0-15:  Tenant ID (GUID, little-endian)
  - Bytes 16-31: Client ID (GUID, little-endian)
```

#### NGC Token

Format: `AQAAAAEAAAABAAAA[Base64Data]`

```
AQAAAAEAAAABAAAA...
│              └─ Payload (variable length)
└─────────────── Fixed 16-byte header
```

#### JWT (Access/ID Token)

Standard JWT format: `header.payload.signature`

```
eyJ0eXAiOiJKV1QiLCJhbGc...
│                        │
└─ Base64URL(header)    └─ Base64URL(payload).Base64URL(signature)
```

### Metadata Extraction

The tool extracts the following metadata when available:

| Field | Source | Description |
|-------|--------|-------------|
| **UPN** | JWT claims / JSON | User Principal Name (email) |
| **Client ID** | JWT `appid/azp` / RT structure | Application (client) identifier |
| **Tenant ID** | JWT `tid` / RT structure | Azure AD tenant identifier |
| **User OID** | JWT `oid` | User's object ID in tenant |
| **Scope** | JWT `scp` | Delegated permissions |
| **Expiration** | JWT `exp` | Token expiration timestamp |
| **Display Name** | JWT `name` | User's display name |
| **Session Key** | JSON metadata | Session-specific key |

---

## 🔐 Detection & OPSEC

### EDR/AV Considerations

**This version includes basic evasion:**

✅ String obfuscation (Base64 encoding)  
✅ Function name obfuscation  
✅ Random sleep delays (behavioral evasion)  
✅ Sanitized output names  

⚠️ **Detection Vectors:**

- **File Access**: Reads authentication cache files
- **DPAPI Calls**: Uses `CryptUnprotectData` API
- **Memory**: Tokens temporarily stored in process memory
- **Disk**: Writes JSON output files to current directory

### OPSEC Best Practices

```bash
# 1. Run from memory (avoid disk writes)
# Use tools like Invoke-ReflectivePEInjection

# 2. Redirect output to memory stream
# Capture JSON in memory instead of files

# 3. Clean up artifacts
del cache_export_*.json
Clear-RecycleBin -Force

# 4. Use in conjunction with other techniques
# Combine with token injection/usage for immediate execution

# 5. Timing considerations
# Run during business hours to blend with normal activity
```

### Defensive Considerations

Organizations can detect this activity by:

1. **Monitoring File Access**:
   - `%LOCALAPPDATA%\Microsoft\TokenBroker\Cache\*`
   - `%LOCALAPPDATA%\Packages\Microsoft.AAD.BrokerPlugin_*\LocalState\*`

2. **API Call Monitoring**:
   - `CryptUnprotectData` / `ProtectedData.Unprotect`
   - Unusual JSON serialization activity

3. **Behavioral Analysis**:
   - Processes reading multiple cache files rapidly
   - Large JSON file creation in unusual locations

4. **Token Misuse Detection**:
   - Unusual API calls from stolen tokens
   - Geographic anomalies (token used from different location)
   - Device compliance violations

---

## 🙏 Credits

### Author

**r3alm0m1x82**  
- Website: [safebreach.it](https://safebreach.it)
- Company: SafeBreach.it
- CyberSecurity Architect / Purple Team / Trainer & Security Researcher

### Inspiration & Research

This tool builds upon research and techniques from:

- **AADBrokerDecrypt** by Jackullrich - winternl.com
- **WAMBam** by Adam Chester - ([@_xpn_](https://twitter.com/_xpn_)
- **ROADtools** by Dirk-jan Mollema ([@_dirkjan](https://twitter.com/_dirkjan))

### Dependencies

- **BouncyCastle.Cryptography** - Cryptographic operations
- **System.Formats.Asn1** - ASN.1 parsing
- **Costura.Fody** - Assembly embedding

---

## 📜 License

```
MIT License

Copyright (c) 2025 r3alm0m1x82

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## ⚡ Quick Reference

```bash
# Clone
git clone https://github.com/r3alm0m1x82/SpecterBroker.git

# Build
cd SpecterBroker && build.bat

# Run
bin\Release\net48\SpecterBroker.exe

# Output
cache_export_type1_*.json  # TBRes format
cache_export_type2_*.json  # BrokerDecrypt format
```

---

**⚠️ Remember: With great power comes great responsibility. Use ethically and legally. ⚠️**

---

*Made with ❤️ for the red team community by r3alm0m1x82*
