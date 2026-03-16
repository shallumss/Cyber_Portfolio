# 🖥️ Active Directory Configuration Lab — EVE-NG + Windows Server 2012 R2

A step-by-step lab walkthrough for deploying an Active Directory Domain Controller inside EVE-NG and joining a Windows 10 client to the domain.

---

## 📋 Overview

This lab covers the full lifecycle of an AD environment setup:

- Uploading a Windows Server 2012 R2 QEMU image to EVE-NG
- Configuring a static IP and promoting the server to a Domain Controller
- Installing and configuring AD DS + DNS roles
- Creating domain users and security groups
- Joining a Windows 10 client VM to the domain and logging in as a domain user

---

## 🧪 Lab Environment

| Component | Details |
|---|---|
| **AD / DC Server** | Windows Server 2012 R2 |
| **DC IP Address** | 150.1.7.115 |
| **Domain** | corvit.local |
| **Client OS** | Windows 10 |
| **Client IP** | 150.1.7.102 |
| **Network** | VMnet1 (Cloud1 in EVE-NG) |
| **Domain User** | it1 / CORVIT\it1 |

---

## 📁 Repository Contents

```
├── README.md
└── AD_Lab_Guide.docx        # Full walkthrough with 16 annotated screenshots
```

---

## 🚀 Quick Start

1. Download the Windows Server 2012 R2 QEMU image
2. Transfer it to `/opt/unetlab/addons/qemu` via WinSCP
3. Run: `/opt/unetlab/wrappers/unl_wrapper -a fixpermissions`
4. Add the node to your EVE-NG topology using **Cloud1 (VMnet1)**
5. Follow the full step-by-step guide in `AD_Lab_Guide.docx`

---

## ✅ Prerequisites

- EVE-NG installed (Community or Pro)
- VMware Workstation with VMnet1 configured
- WinSCP for file transfer to the EVE-NG host
- Windows 10 VM connected to VMnet1

---

## 📖 Full Guide

The complete walkthrough (`AD_Lab_Guide.docx`) includes:

- **Part 1** — Setting up the AD server in EVE-NG (Steps 1–9, Figures 1–11)
- **Part 2** — Joining a Windows 10 client to the domain (Steps 1–4, Figures 12–16)
- **Part 3** — Best practices, verification commands, and troubleshooting tips

---

## 🔧 Useful Verification Commands

```powershell
# Verify client can locate the Domain Controller
nltest /dsgetdc:corvit.local

# Confirm logged-in domain user
whoami

# Check applied Group Policy Objects
gpresult /r

# View domain user account details
net user it1 /domain
```

---

## 📝 Notes

- Always point domain-joined machines' DNS to the DC (`150.1.7.115`), never to an external DNS
- Do not log in as domain users directly on the Domain Controller
- Disable NAT adapters on the client VM before joining the domain to avoid DNS conflicts
