#!/bin/sh
#
# Install Qubes Snitch into the current Qubes TemplateVM
# Run this from the cloned repo root inside tpl-qubes-snitch, then create sys-snitch from that template
# Tested with the Qubes OS debian-13-minimal template

set -eux



# libnotify-bin provides notify-send, xfce4-notifyd shows the popup, and dbus-x11 supplies DBus bits in minimal templates
# xfce4-terminal is used by the desktop launcher because XFCE is the default Qubes desktop
# python3-dnspython parses UDP DNS questions so Snitch can ask about domains separately from resolver IP traffic
apt-get install -y nftables conntrack python3-yaml python3-qubesdb python3-netfilterqueue python3-dnspython libnotify-bin xfce4-notifyd dbus-x11 xfce4-terminal

# Create all install directories with normal root-readable permissions before copying files into them
install -d -m 0755 /etc/qubes-snitch /rw/usrlocal/qubes-snitch/rules /usr/lib/python3/dist-packages/qubes_snitch /usr/lib/qubes-snitch /usr/share/applications /usr/share/icons/hicolor/scalable/apps

# Put shared modules in Python's normal import path so both CLI and daemon can import qubes_snitch
install -m 0644 qubes_snitch/*.py /usr/lib/python3/dist-packages/qubes_snitch/

# Install the public command names without .py so users and systemd call qubes-snitch/qubes-snitchd
install -m 0755 qubes-snitchd.py /usr/sbin/qubes-snitchd
install -m 0755 qubes-snitch.py /usr/bin/qubes-snitch
install -m 0644 templates/etc/qubes-snitch/config.yml /etc/qubes-snitch/config.yml
install -m 0644 templates/etc/systemd/system/qubes-snitch-fail-closed.service /etc/systemd/system/qubes-snitch-fail-closed.service
install -m 0644 templates/etc/systemd/system/qubes-snitchd.service /etc/systemd/system/qubes-snitchd.service
install -m 0644 templates/usr/lib/qubes-snitch/fail-closed.nft /usr/lib/qubes-snitch/fail-closed.nft
install -m 0755 templates/usr/lib/qubes-snitch/stop-post.sh /usr/lib/qubes-snitch/stop-post.sh
install -m 0644 templates/usr/share/applications/qubes-snitch.desktop /usr/share/applications/qubes-snitch.desktop
install -m 0644 templates/usr/share/icons/hicolor/scalable/apps/qubes-snitch.svg /usr/share/icons/hicolor/scalable/apps/qubes-snitch.svg

# Enable the daemon so sys-snitch starts enforcing policy on boot
systemctl enable qubes-snitch-fail-closed.service
systemctl enable qubes-snitchd.service
