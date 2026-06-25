# Purpose: shared helpers for importing Qubes Snitch scripts in normal unit tests
# Scope: replaces dnspython and netfilterqueue with tiny fakes so tests run without root or a live NFQUEUE
import importlib
import importlib.machinery
import importlib.util
import sys
import types
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
SNITCHD = REPO / "qubes-snitchd.py"
SNITCH_CLI = REPO / "qubes-snitch.py"
INSTALL_SH = REPO / "install.sh"
INSTALL_DOM0_SH = REPO / "install-dom0.sh"


class FakeDnsName:
    # Fake DNS name object with text rendering and raw label bytes
    def __init__(self, text, labels=None):
        self.text = text
        self.labels = labels or tuple(label.encode("ascii") for label in text.rstrip(".").split(".")) + (b"",)

    def __str__(self):
        return self.text


class FakeQuestion:
    # Fake DNS question object with the fields add_dns_query_fields reads
    def __init__(self, name, rdtype, rdclass=1):
        self.name = name if hasattr(name, "labels") else FakeDnsName(name)
        self.rdtype = rdtype
        self.rdclass = rdclass



class FakeDnsMessage(types.ModuleType):
    # Fake dns.message module; from_wire returns predictable query/answer objects for byte fixtures
    def __init__(self):
        # Register as a module-like object so import dns.message works
        super().__init__("dns.message")

    def from_wire(self, payload):
        # Byte fixtures keep DNS tests readable without storing binary packet captures
        if payload == b"query-a":
            return types.SimpleNamespace(question=[FakeQuestion("Example.COM.", 1)], answer=[])
        if payload == b"\xf6\xbequery-a":
            return types.SimpleNamespace(question=[FakeQuestion("forum.qubes-os.org.", 1)], answer=[])
        if payload == b"query-aaaa":
            return types.SimpleNamespace(question=[FakeQuestion("Example.COM.", 28)], answer=[])
        if payload == b"query-multi":
            return types.SimpleNamespace(question=[FakeQuestion("Allowed.COM.", 1), FakeQuestion("Blocked.COM.", 1)], answer=[])
        if payload == b"query-ch":
            return types.SimpleNamespace(question=[FakeQuestion("Example.COM.", 1, 3)], answer=[])
        if payload == b"query-mx":
            return types.SimpleNamespace(question=[FakeQuestion("Example.COM.", 15)], answer=[])
        if payload == b"query-srv":
            return types.SimpleNamespace(question=[FakeQuestion("_http._tcp.Example.COM.", 33)], answer=[])
        if payload == b"query-srv-single-label":
            return types.SimpleNamespace(question=[FakeQuestion("_http._tcp.localhost.", 33)], answer=[])
        if payload == b"query-xn":
            return types.SimpleNamespace(question=[FakeQuestion("xn--pple-43d.example.", 1)], answer=[])
        if payload == b"query-non-ascii-qname":
            name = FakeDnsName("\\255.example.com.", (b"\xff", b"example", b"com", b""))
            return types.SimpleNamespace(question=[FakeQuestion(name, 1)], answer=[])
        if payload == b"query-any":
            return types.SimpleNamespace(question=[FakeQuestion("Example.COM.", 255)], answer=[])
        if payload == b"query-additional":
            return types.SimpleNamespace(question=[FakeQuestion("Example.COM.", 1)], answer=[], additional=[object()])
        if payload == b"query-ra-flag":
            return types.SimpleNamespace(flags=FakeDnsFlags.RA, question=[FakeQuestion("Example.COM.", 1)], answer=[])
        if payload == b"query-rcode-refused":
            return types.SimpleNamespace(flags=FakeDnsRcode.REFUSED, question=[FakeQuestion("Example.COM.", 1)], answer=[])
        if payload == b"query-rd-flag":
            return types.SimpleNamespace(flags=FakeDnsFlags.RD, question=[FakeQuestion("Example.COM.", 1)], answer=[])
        if payload == b"query-edns-v1":
            return types.SimpleNamespace(edns=1, question=[FakeQuestion("Example.COM.", 1)], answer=[])
        if payload == b"query-edns-extended-rcode":
            return types.SimpleNamespace(edns=0, ednsflags=0, rcode=lambda: 16, question=[FakeQuestion("Example.COM.", 1)], answer=[])
        if payload == b"query-edns-reserved-flag":
            return types.SimpleNamespace(edns=0, ednsflags=0x4000, question=[FakeQuestion("Example.COM.", 1)], answer=[])
        if payload == b"query-edns-do-flag":
            return types.SimpleNamespace(edns=0, ednsflags=0x8000, question=[FakeQuestion("Example.COM.", 1)], answer=[])
        if payload == b"query-ad-flag":
            return types.SimpleNamespace(flags=FakeDnsFlags.AD, question=[FakeQuestion("Example.COM.", 1)], answer=[])
        if payload == b"query-cd-flag":
            return types.SimpleNamespace(flags=FakeDnsFlags.CD, question=[FakeQuestion("Example.COM.", 1)], answer=[])
        if payload == b"query-edns":
            return types.SimpleNamespace(question=[FakeQuestion("Example.COM.", 1)], answer=[], additional=[], options=[object()])
        if payload == b"query-two-edns":
            return types.SimpleNamespace(question=[FakeQuestion("Example.COM.", 1)], answer=[], additional=[], options=[object(), object()])
        if payload == b"query-wildcard":
            return types.SimpleNamespace(question=[FakeQuestion("*.Example.COM.", 1)], answer=[])
        if payload == b"query-root":
            return types.SimpleNamespace(question=[FakeQuestion(".", 2)], answer=[])
        if payload == b"query-ip6-ptr":
            return types.SimpleNamespace(question=[FakeQuestion("8.b.d.0.1.0.0.2.ip6.arpa.", 12)], answer=[])
        if payload == b"query-bad-leading":
            return types.SimpleNamespace(question=[FakeQuestion("-bad.example.", 1)], answer=[])
        if payload == b"query-bad-escape":
            return types.SimpleNamespace(question=[FakeQuestion("foo\\046.example.", 1)], answer=[])
        raise ValueError("bad dns packet")

    def make_response(self, query):
        # Synthetic reject tests need a response-like object with answer and to_wire()
        response = types.SimpleNamespace(answer=[], rcode_value=0)
        response.set_rcode = lambda rcode: setattr(response, "rcode_value", rcode)
        response.to_wire = lambda: f"dns-response-rcode-{response.rcode_value}-answers-{len(response.answer)}".encode("utf-8")
        return response


class FakeDnsException(types.ModuleType):
    # dns.py catches this fake parse exception the same way it catches real dnspython parse errors
    DNSException = ValueError


class FakeRdatatype(types.ModuleType):
    # Fake dns.rdatatype module with only the qtypes used by the tests
    A = 1
    CNAME = 5

    def __init__(self):
        # Register as a module-like object so import dns.rdatatype works
        super().__init__("dns.rdatatype")

    def from_text(self, text):
        # Validate manual qtype text with the small set and TYPE#### form used in tests
        upper = str(text).upper()
        if upper == "A":
            return 1
        mapping = {"CNAME": 5, "MX": 15, "TXT": 16, "SRV": 33, "PTR": 12, "CAA": 257, "NS": 2, "SOA": 6, "HTTPS": 65, "SVCB": 64, "NAPTR": 35, "DS": 43, "DNSKEY": 48, "RRSIG": 46, "NSEC": 47, "NSEC3": 50, "ANY": 255}
        if upper in mapping:
            return mapping[upper]
        if upper == "AAAA":
            return 28
        if upper.startswith("TYPE") and upper[4:].isdigit():
            value = int(upper[4:])
            if 1 <= value <= 65535:
                return value
        raise ValueError("unknown dns qtype")

    def to_text(self, rdtype):
        # Convert the numeric qtype from fake questions into the same text YAML stores
        return {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3", 64: "SVCB", 65: "HTTPS", 255: "ANY", 257: "CAA"}.get(rdtype, f"TYPE{rdtype}")

class FakeRdataclass(types.ModuleType):
    # Fake dns.rdataclass module for IN-class enforcement
    IN = 1

    def __init__(self):
        super().__init__("dns.rdataclass")

    def to_text(self, rdclass):
        return {1: "IN", 3: "CH"}.get(rdclass, f"CLASS{rdclass}")


class FakeDnsFlags(types.ModuleType):
    # Real dnspython marks responses with the QR bit
    QR = 0x8000
    AA = 0x0400
    TC = 0x0200
    RD = 0x0100
    RA = 0x0080
    AD = 0x0020
    CD = 0x0010

    def __init__(self):
        super().__init__("dns.flags")


class FakeDnsRcode(types.ModuleType):
    # REFUSED is used for synthetic policy rejects
    NOERROR = 0
    REFUSED = 5

    def __init__(self):
        super().__init__("dns.rcode")


class FakeRrset(types.ModuleType):
    # Fake dns.rrset module used when dns.py builds a synthetic reject response
    def __init__(self):
        # Register as a module-like object so import dns.rrset works
        super().__init__("dns.rrset")

    def from_text(self, *args):
        # dns.py only passes this through to message.make_response in tests, so the args tuple is enough
        return args

class FakeResolver(types.ModuleType):
    # Tests can monkeypatch resolve; default raises like a lookup failure
    def __init__(self):
        super().__init__("dns.resolver")

    def resolve(self, *_args, **_kwargs):
        raise RuntimeError("no fake resolver answer")


class FakeReversename(types.ModuleType):
    # Fake reverse-name module keeps PTR fallback tests independent from dnspython
    def __init__(self):
        super().__init__("dns.reversename")

    def from_address(self, ip):
        return f"reverse-{ip}"


def load_snitchd():
    # Install fake modules before importing scripts because qubes-snitchd imports runtime dependencies at module load
    nfq = types.ModuleType("netfilterqueue")
    nfq.NetfilterQueue = object
    sys.modules["netfilterqueue"] = nfq
    # Test hosts usually lack QubesDB, so fake only the constructor imported at daemon load
    qubesdb = types.ModuleType("qubesdb")
    setattr(qubesdb, "QubesDB", object)
    sys.modules["qubesdb"] = qubesdb
    dns_pkg = types.ModuleType("dns")
    dns_exception = FakeDnsException("dns.exception")
    dns_flags = FakeDnsFlags()
    dns_message = FakeDnsMessage()
    dns_rcode = FakeDnsRcode()
    dns_rdataclass = FakeRdataclass()
    dns_rdatatype = FakeRdatatype()
    dns_resolver = FakeResolver()
    dns_reversename = FakeReversename()
    dns_rrset = FakeRrset()
    setattr(dns_pkg, "exception", dns_exception)
    setattr(dns_pkg, "flags", dns_flags)
    setattr(dns_pkg, "message", dns_message)
    setattr(dns_pkg, "rcode", dns_rcode)
    setattr(dns_pkg, "rdataclass", dns_rdataclass)
    setattr(dns_pkg, "rdatatype", dns_rdatatype)
    setattr(dns_pkg, "resolver", dns_resolver)
    setattr(dns_pkg, "reversename", dns_reversename)
    setattr(dns_pkg, "rrset", dns_rrset)
    sys.modules["dns"] = dns_pkg
    sys.modules["dns.exception"] = dns_exception
    sys.modules["dns.flags"] = dns_flags
    sys.modules["dns.message"] = dns_message
    sys.modules["dns.rcode"] = dns_rcode
    sys.modules["dns.rdataclass"] = dns_rdataclass
    sys.modules["dns.rdatatype"] = dns_rdatatype
    sys.modules["dns.resolver"] = dns_resolver
    sys.modules["dns.reversename"] = dns_reversename
    sys.modules["dns.rrset"] = dns_rrset
    for name in (
        "qubes_snitch.config",
        "qubes_snitch.notify",
        "qubes_snitch.nft",
        "qubes_snitch.policy",
        "qubes_snitch.alerts_runtime",
        "qubes_snitch.dns",
        "qubes_snitch.dns_cache_runtime",
        "qubes_snitch.packet_handlers",
        "qubes_snitch.policy_runtime",
        "qubes_snitch.sources_runtime",
    ):
        if name in sys.modules:
            importlib.reload(sys.modules[name])
    loader = importlib.machinery.SourceFileLoader("qubes_snitchd_test", str(REPO / "qubes_snitch" / "daemon_runtime.py"))
    spec = importlib.util.spec_from_loader("qubes_snitchd_test", loader)
    if spec is None:
        raise RuntimeError("failed to load snitchd module spec")
    module = importlib.util.module_from_spec(spec)
    sys.modules["qubes_snitchd_test"] = module
    loader.exec_module(module)
    from qubes_snitch import alerts_runtime, config, dns_cache_runtime, nft, notify, packets, policy
    from qubes_snitch.dns import add_dns_query_fields
    from qubes_snitch.packets import request_without_body
    module.alerts_runtime = alerts_runtime
    module.config = config
    module.dns = dns_pkg
    module.dns_cache_runtime = dns_cache_runtime
    module.nft = nft
    module.notify = notify
    module.packets = packets
    module.policy = policy
    module.add_dns_query_fields = add_dns_query_fields
    module.request_without_body = request_without_body
    module.CONFIG = {"notify_send": False, "pending_queue_size": 200, "dns_cache_max_per_source": 32768, "dns_cache_max_global": 131072, "dns_cache_refresh_workers": 32, "default_disposable_vm_name": "default-dvm", "limit_rate": "3/minute", "burst": 5, "log_bucket_max_entries": 4096, "prompt_protocol_colors": {"encrypted": {("tcp", "443")}, "unencrypted": {("tcp", "80"), ("udp", "53")}}}
    return module


def load_cli():
    # Import the CLI script as a module so tests can call helpers without starting the infinite main loop
    loader = importlib.machinery.SourceFileLoader("qubes_snitch_cli_test", str(SNITCH_CLI))
    spec = importlib.util.spec_from_loader("qubes_snitch_cli_test", loader)
    if spec is None:
        raise RuntimeError("failed to load snitch CLI module spec")
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module

