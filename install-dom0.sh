#!/bin/sh
#
# Install Qubes Snitch from dom0 and create sys-snitch
# Download this script through a DisposableVM, read it in dom0, chmod 700 it, then run ./install-dom0.sh

set -eux


# Fixed install names used by the first simple installer version
BASE_TEMPLATE=debian-13-minimal
SNITCH_TEMPLATE=tpl-qubes-snitch
SNITCH_VM=sys-snitch
REPO_URL=https://github.com/kuhbs/qubes-snitch
RPC_SERVICE=qubes.SnitchSources
RPC_POLICY=/etc/qubes/policy.d/30-qubes-snitch.policy


# Refuse early so an existing template or VM is never silently modified
if qvm-check --quiet "$SNITCH_TEMPLATE"; then
    printf '%s\n' "refusing to continue because $SNITCH_TEMPLATE already exists" >&2
    exit 1
elif qvm-check --quiet "$SNITCH_VM"; then
    printf '%s\n' "refusing to continue because $SNITCH_VM already exists" >&2
    exit 1
fi


# Install the small Debian base template that tpl-qubes-snitch will be cloned from
qvm-template install "$BASE_TEMPLATE"
# Clone a dedicated template so Snitch packages and files do not alter the generic Debian template
qvm-clone "$BASE_TEMPLATE" "$SNITCH_TEMPLATE"


# Install Git inside tpl-qubes-snitch because dom0 should not clone or build project files directly
qvm-run -u root -p "$SNITCH_TEMPLATE" 'apt-get update && apt-get install -y git'
# Clone the repository as user so the checkout is not root-owned inside the template
qvm-run -u user -p "$SNITCH_TEMPLATE" "rm -rf /home/user/qubes-snitch && git clone '$REPO_URL' /home/user/qubes-snitch"
# Run install.sh as root because it writes /usr, /etc, and systemd files inside the template
qvm-run -u root -p "$SNITCH_TEMPLATE" 'cd /home/user/qubes-snitch && ./install.sh'
# Copy the dom0 source-map helper from the cloned template checkout into dom0
source_helper=$(mktemp)
qvm-run --pass-io --no-gui --user user "$SNITCH_TEMPLATE" \
    'cat /home/user/qubes-snitch/templates/dom0/usr/local/lib/qubes-snitch/sources.py' \
    > "$source_helper"
sudo install -d -m 0755 /usr/local/lib/qubes-snitch
sudo install -m 0644 "$source_helper" /usr/local/lib/qubes-snitch/sources.py
rm -f "$source_helper"

# Shut down the template before creating sys-snitch so the new AppVM sees all installed files
qvm-shutdown --wait "$SNITCH_TEMPLATE"


# Create the dom0 qrexec service that lets sys-snitch ask for downstream VM identity only
sudo tee "/etc/qubes-rpc/$RPC_SERVICE" >/dev/null <<EOF
#!/bin/sh
SNITCH_VM=$SNITCH_VM exec python3 /usr/local/lib/qubes-snitch/sources.py
EOF
sudo chmod 755 "/etc/qubes-rpc/$RPC_SERVICE"

# Allow only sys-snitch to call the read-only source identity service
sudo tee "$RPC_POLICY" >/dev/null <<EOF
$RPC_SERVICE * $SNITCH_VM @adminvm allow
$RPC_SERVICE * @anyvm @adminvm deny
EOF


# Create sys-snitch as the ProxyVM users will route other VMs through
qvm-create --class AppVM --template "$SNITCH_TEMPLATE" --label purple "$SNITCH_VM"
# provides_network=True lets other VMs choose sys-snitch as their NetVM
qvm-prefs "$SNITCH_VM" provides_network True
# Autostart sys-snitch on boot
qvm-prefs "$SNITCH_VM" autostart True
# Keep Qubes network plumbing enabled for forwarding, NAT, DNS DNAT, and virtual-interface setup
qvm-service "$SNITCH_VM" qubes-network on
# Keep Qubes firewall service enabled for Qubes plumbing while Snitch owns user allow/reject policy
qvm-service "$SNITCH_VM" qubes-firewall on


# Refresh Qubes appmenus so dom0 XFCE sees the .desktop launcher installed in the template
qvm-appmenus --update --force "$SNITCH_VM"


# Keep final output short because upstream NetVM choice and first test VM are user-specific README steps
echo
echo "Qubes-Snitch installation completed :) Refer to README.md for how to continue from here"
