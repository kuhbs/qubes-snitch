import ipaddress
import os
import xml.etree.ElementTree as ET

SNITCH_VM = os.environ["SNITCH_VM"]
QUBES_XML = "/var/lib/qubes/qubes.xml"


def prop(domain, name):
    node = domain.find(f"./properties/property[@name='{name}']")
    if node is None:
        return None
    value = node.get("ref")
    if value is None:
        value = node.text
    return value or None


def qid(domain):
    ident = domain.get("id", "")
    if not ident.startswith("domain-"):
        return None
    try:
        return int(ident.split("-", 1)[1])
    except ValueError:
        return None


def ip_from_id(prefix, value):
    if value is None:
        return None
    value = int(value)
    if value < 255:
        return f"{prefix}.{(value >> 8) & 255}.{value & 255}"
    value -= 1
    return f"{prefix}.{value // 254}.{(value % 254) + 1}"


def label_name(value):
    if value is None:
        return None
    if value.startswith("label-"):
        return value[6:]
    return value


def vm_uses_snitch(name, netvms):
    seen = set()
    vm = name
    while vm and vm != "-" and vm not in seen:
        if vm == SNITCH_VM:
            return True
        seen.add(vm)
        vm = netvms.get(vm)
    return False


def main():
    tree = ET.parse(QUBES_XML)
    root = tree.getroot()
    default_netvm = prop(root, "default_netvm")
    rows = []
    netvms = {}

    for domain in root.findall("./domains/domain"):
        name = prop(domain, "name")
        if not name or name == "dom0":
            continue
        vm_class = domain.get("class") or "-"
        netvm = prop(domain, "netvm")
        if netvm is None and vm_class != "TemplateVM":
            netvm = default_netvm
        if netvm:
            netvms[name] = netvm
        template = prop(domain, "template") or "-"
        ip = prop(domain, "ip")
        if ip is None:
            if vm_class == "DispVM":
                ip = ip_from_id("10.138", prop(domain, "dispid"))
            else:
                ip = ip_from_id("10.137", qid(domain))
        label = label_name(prop(domain, "label"))
        rows.append((name, ip, label, vm_class, template))

    for name, ip, label, vm_class, template in rows:
        if not ip or not label:
            continue
        try:
            if ipaddress.ip_address(ip).version != 4:
                continue
        except ValueError:
            continue
        if not vm_uses_snitch(name, netvms):
            continue
        print(f"{name}|{ip}|{label}|{vm_class}|{template}")


if __name__ == "__main__":
    main()
