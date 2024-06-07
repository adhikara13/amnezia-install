[English](README.md) | [Vídeo en Español](https://www.youtube.com/watch?v=99qtaJU2E2k)

# Amnezia VPN Server Auto Setup Script

[![License: MIT](docs/images/license.svg)](https://opensource.org/licenses/MIT)

Amnezia VPN server installer for Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS, Fedora, openSUSE and Raspberry Pi OS.

This script will let you set up your own VPN server in just a few minutes, even if you haven't used Amnezia before. [Amnezia](https://www.Amnezia.org) is a fast and modern VPN designed with the goals of ease of use and high performance.


## Features

- Fully automated Amnezia VPN server setup, no user input needed
- Supports interactive install using custom options
- Generates VPN profiles to auto-configure Windows, macOS, iOS and Android devices
- Supports managing Amnezia VPN users
- Optimizes `sysctl` settings for improved VPN performance

## Installation

First, download the script on your Linux server\*:

```bash
wget -O amnezia.sh https://get.vpnsetup.net/wg
```

**Option 1:** Auto install Amnezia using default options.

```bash
sudo bash amnezia.sh --auto
```

<details>
<summary>
See the script in action (terminal recording).
</summary>

**Note:** This recording is for demo purposes only.

<p align="center"><img src="docs/images/demo1.svg"></p>
</details>

For servers with an external firewall (e.g. [EC2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html)/[GCE](https://cloud.google.com/firewall/docs/firewalls)), open UDP port 51820 for the VPN.

**Option 2:** Interactive install using custom options.

```bash
sudo bash amnezia.sh
```

You can customize the following options: VPN server's DNS name, UDP port, DNS server for VPN clients and name of the first client.

For servers with an external firewall, open your selected UDP port for the VPN.

<details>
<summary>
Click here if you are unable to download.
</summary>

You may also use `curl` to download:

```bash
curl -fL -o amnezia.sh https://get.vpnsetup.net/wg
```

Then follow the instructions above to install.

Alternative setup URLs:

```bash
https://github.com/hwdsl2/Amnezia-install/raw/master/Amnezia-install.sh
https://gitlab.com/hwdsl2/Amnezia-install/-/raw/master/Amnezia-install.sh
```

If you are unable to download, open [Amnezia-install.sh](Amnezia-install.sh), then click the `Raw` button on the right. Press `Ctrl/Cmd+A` to select all, `Ctrl/Cmd+C` to copy, then paste into your favorite editor.
</details>
<details>
<summary>
Advanced: Auto install using custom options.
</summary>

Advanced users can auto install Amnezia using custom options, by providing a Bash "here document" as input to the setup script. This method can also be used to provide input to manage users after install.

First, install Amnezia interactively using custom options, and write down all your inputs to the script.

```bash
sudo bash amnezia.sh
```

If you need to remove Amnezia, run the script again and select the appropriate option.

Next, create the custom install command using your inputs. Example:

```bash
sudo bash amnezia.sh <<ANSWERS
n
51820
client
2
y
ANSWERS
```

**Note:** The install options may change in future versions of the script.
</details>

\* A cloud server, virtual private server (VPS) or dedicated server.

## Next steps

After setup, you can run the script again to manage users or uninstall Amnezia.

Get your computer or device to use the VPN. Please refer to:

**[Configure Amnezia VPN Clients](docs/clients.md)**


Enjoy your very own VPN! :sparkles::tada::rocket::sparkles:



## License

MIT
