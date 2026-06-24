#!/bin/sh
# Restore fail-closed nft rules after qubes-snitchd exits
# Alert the desktop if the daemon failed or fail-closed restore failed

rc=0
/usr/sbin/nft -f /usr/lib/qubes-snitch/fail-closed.nft || rc=$?

if [ "$rc" -ne 0 ] || [ "$SERVICE_RESULT" != success ]; then
    vm="$(/usr/bin/hostname)"
    DISPLAY=:0 \
        XDG_RUNTIME_DIR=/run/user/1000 \
        DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus \
        /usr/sbin/runuser -u user -- \
        /usr/bin/notify-send --icon=/usr/share/icons/hicolor/scalable/apps/qubes-snitch.svg -u critical "$vm" "systemd qubes-snitchd.service STOPPED WITH ERROR!" || { [ "$rc" -ne 0 ] || rc=$?; }
fi

exit "$rc"
