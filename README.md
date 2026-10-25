[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# OWASP WAFControl Installer

The **OWASP WAFControl** project provides a web-based dashboard and management interface for ModSecurity and the OWASP Core Rule Set (CRS).  
It simplifies installation, configuration, and operation of CRS and ModSecurity, enabling administrators and security engineers to deploy, monitor, and manage WAF rules more effectively.


## Easy Install

```bash
curl -fsSL https://wafcontrol.org/download/install.sh -o install.sh
```

```bash
chmod +x install.sh
```

```bash
sudo ./install.sh
```

When running from a checkout, the installer uses the modules in the adjacent
`modules/` directory. Setting `MODULE_BASE` explicitly selects remote modules
instead. A standalone downloaded `install.sh` fetches remote modules as before.

## Nginx / ModSecurity compatibility

The Nginx installer uses the `modsecurity` pkg-config metadata to select the
library and downloads `modsecurity.conf-recommended` and `unicode.mapping` from
that exact v3 release. It installs `libmodsecurity-dev`, which resolves the
runtime package name on each distribution (including `libmodsecurity3t64` on
Ubuntu 24.04), and checks the configuration with Nginx before enabling it.

Earlier installers could copy an Apache/v2 or newer configuration into Nginx.
The error `Expecting a variable ... MULTIPART_DUPLICATE_PART_HEADER` means the
configuration refers to a variable the loaded engine does not recognize. The
variable was introduced in [ModSecurity v3.0.17](https://github.com/owasp-modsecurity/ModSecurity/releases/tag/v3.0.17);
Ubuntu 24.04 packages [v3.0.12](https://packages.ubuntu.com/en/noble/libs/libmodsecurity3t64).
The updated module backs up and repairs this diagnostic text on older engines,
while retaining multipart strict validation and existing local settings.

To repair this specific error on an already installed server without rerunning
the application/database installation:

```bash
sudo bash <<'BASH'
set -euo pipefail
conf=/etc/nginx/modsec/modsecurity.conf
backup="${conf}.bak.$(date +%s)"
cp -a -- "$conf" "$backup"
sed -i -E 's/DH[[:blank:]]+%\{MULTIPART_DUPLICATE_PART_HEADER\},[[:blank:]]*//g' "$conf"
if nginx -t; then
  systemctl reload nginx
else
  cp -a -- "$backup" "$conf"
  exit 1
fi
BASH
```

Run the offline regression checks with:

```bash
python3 -m unittest discover -s tests -v
```

## Uninstall

WAFControl provides an interactive and safe uninstallation process.

⚠️ IMPORTANT

If Nginx or PostgreSQL were already installed on your server before WAFControl, DO NOT remove them.
Removing Nginx or PostgreSQL may break other applications and cause irreversible data loss.
If you remove them anyway, the responsibility is entirely yours.

This BASH uninstall removes only the files and components added by WAFControl and does not modify NGINX or PostgreSQL (or any other system services).
If PostgreSQL already existed on your server or contains data you want to remove, you must handle/remove it manually if needed.
The OWASP WAFControl project and its contributors are not responsible for any data loss caused by manual or forced removal of system services.

```bash
curl -fsSL https://raw.githubusercontent.com/wafcontrol/install/refs/heads/main/uninstall.sh -o uninstall.sh
```

```bash
chmod +x uninstall.sh
```

```bash
sudo ./uninstall.sh
```


## WAFControl Resources
- [OWASP WAFControl Project Site](https://wafcontrol.org/)
- [OWASP WAFControl Project Page](https://owasp.org/www-project-wafcontrol/)  

## Documentation
- [OWASP WAFControl Docs](https://wafcontrol.org/docs)


## License

Copyright (c) 2025 OWASP WAFControl Project.  
All rights reserved.  

The OWASP WAFControl project is distributed under the Apache Software License (ASL) version 2.0.  
See the enclosed [LICENSE](./LICENSE) file for full details.
