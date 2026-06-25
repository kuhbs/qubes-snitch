# Qubes-Snitch audit notes

This file records answers to repeated AI audit findings so future reviews can avoid re-reporting already-decided issues.

## Threat model reminders

- Manual edits to `config.yml` and rule YAML files are trusted user/admin input
- The protected client VM is not trusted
- The local `user` and root accounts inside `sys-snitch` are trusted
- dom0 and Qubes qrexec policy are trusted
- Qubes-Snitch is IPv4-only by design
- Qubes-Snitch depends on Qubes' own ProxyVM plumbing and anti-spoofing before its own policy layer

## False positives / do not re-report as bugs

### CLI input cannot inject arbitrary YAML fields

The CLI does not send rule fields such as `qname`, `qtype`, `dst`, `proto`, or `port` to the daemon.

The daemon sends one JSON prompt to the CLI, and the CLI sends back only one decision line: `allow` or `reject`. Rule fields are derived from daemon-side packet parsing and DNS parsing. Generated YAML is validated with the normal rule-file validator before it is atomically installed with `os.replace()`.

### Malformed packets do not become prompts or rules

Malformed packets are dropped before prompt queueing.

Malformed DNS and malformed IP/TCP/UDP/ICMP packets are logged/notified according to the security path and are not persisted as allow/reject policy. Unsupported-but-normal DNS can receive DNS `REFUSED`; suspicious or malformed DNS is dropped instead.

### Defensive TCP/UDP port checks are not reachable from normal prompt flow

`append_flow_rule()` refuses to persist a TCP/UDP rule without a destination port. This is defensive fail-closed code, not a reachable CLI crash bug.

Packet parsing marks TCP/UDP source port 0, destination port 0, missing transport ports, and malformed TCP/UDP headers as malformed. Malformed packets are dropped before prompt queueing. The CLI cannot invent `dport`, `dst`, `proto`, or other rule fields; it only returns `allow` or `reject` for a daemon-created pending prompt.

### Unicode/IDN DNS names are not accepted by live DNS policy

Python `re` character ranges such as `[a-z]` do not match Cyrillic/CJK characters. Live DNS qnames are restricted by ASCII-range regexes and additional checks that reject punycode/IDN labels.

This is intentional, not missing IDN support. DNS decisions must stay readable and must not silently accept homograph lookalikes such as `раураl.com`, `gооgle.com`, or `аррӏе.com`.

Qubes-Snitch rejects non-ASCII text at the relevant input boundaries: raw DNS packet bodies containing non-ASCII bytes are dropped before DNS parsing, PTR lookup results containing non-ASCII text are not displayed, and config/rule/source files are rejected before use if they contain non-ASCII bytes. Do not report Unicode DNS/PTR/config/source text as accepted unless a path bypasses these ASCII gates.

Qubes-Snitch is not a network intrusion detection system. It normally does not classify arbitrary packet contents as malicious; it prompts for firewall policy. Unicode DNS/PTR text is the exception because Snitch would already be interpreting that text for a user decision, and forwarding malicious, confusing, or hard-to-see Unicode to the CLI would make the prompt less trustworthy.

### YAML parsing is intentionally safe-loader only

Qubes-Snitch uses a `yaml.SafeLoader`-derived loader that also rejects duplicate keys. Do not report unsafe YAML deserialization unless a new code path uses an unsafe loader.

Generated rule YAML is reloaded and validated before it is published. A broken generated rule fails closed instead of becoming live policy.

### subprocess calls are argv lists, not shell strings

Qubes-Snitch intentionally avoids `shell=True`, `eval`, `exec`, `pickle`, `os.system`, and `os.popen`. Calls to `nft`, `notify-send`, `runuser`, and qrexec helpers use list argv.

Do not report shell metacharacters in packet fields, PTR names, DNS names, or VM names as shell injection unless a future change introduces a shell sink.

### nftables rendering does not use PTR or qname as syntax

Saved flow rules render validated `dest`, `proto`, `port`, source-chain names, and `action`. Destination values are validated as IPv4 networks or the explicit `any` sentinel, protocols/actions are restricted vocabularies, ports are normalized, chain names are sanitized and hashed, and log prefixes are quoted.

PTR names and DNS qnames are display/policy data, not nft syntax fragments for normal flow matching. Do not report PTR-controlled nft injection unless the renderer starts using PTR text in match expressions.

### `ip_network(..., strict=False)` is not a policy bypass

Qubes-Snitch accepts trusted manual YAML networks through `ipaddress.ip_network(value, strict=False)`. This only normalizes non-canonical CIDR text with host bits set, for example `10.0.0.1/24` to `10.0.0.0/24`; it does not broaden nftables matching beyond the normalized network.

Manual YAML is trusted user/admin input, and `0.0.0.0/0` is explicitly rejected in favor of the visible `dest: any` sentinel. Do not report `strict=False` as a vulnerability without showing a different accepted match set between Python validation and nftables rendering.

### DNS wildcard suffix matching is intentional and apex-safe

Manual wildcard DNS rules use suffix matching: `*.example.org` matches `www.example.org`, but not the bare apex `example.org` and not `badexample.org`. Live DNS prompts create exact qname rules; wildcard rules are manual policy only.

Do not report DNS wildcard overmatching unless a future change removes the `qname.endswith("." + suffix) and qname != suffix` shape.

### DNS wire parsing is delegated to dnspython

DNS packets are parsed with dnspython instead of a hand-rolled compression-pointer parser. Malformed DNS is rejected or dropped before it can become saved policy.

Do not report DNS compression-pointer loops or malformed-wire crashes without demonstrating that dnspython raises something outside the handled DNS exception path in the current packet path.

### NFQUEUE policy is intentionally fail-closed

Rendered queue rules do not use the nftables `bypass` flag, and the forward base chain policy is drop. If the daemon is absent, dead, or overloaded, queued traffic does not silently pass.

Do not report daemon death or full queues as fail-open unless a queue rule gains `bypass` or the base policy stops being drop.

### Terminal and syslog spoofing are filtered before display

Attacker-influenced display fields pass through `safe_text()` before terminal/syslog output. Control characters, format characters, ESC, and BiDi overrides are stripped or collapsed.

Do not report ANSI escape injection or BiDi prompt spoofing unless a new output path prints untrusted text without `safe_text()`.

### qrexec source inventory does not take attacker-controlled arguments

`sys-snitch` does not pass attacker-controlled arguments to the dom0 source helper. The dom0 helper reads Qubes state and returns pipe-separated source rows, and the daemon validates row shape, source names, IPv4 addresses, duplicate IPs, and label conflicts.

Do not report qrexec argument injection or unvalidated source inventory unless a future helper starts consuming untrusted stdin/argv or the daemon stops validating returned rows.

### Source inventory size is bounded by Qubes-managed VM state

The protected client VM cannot write arbitrary source rows into QubesDB or the dom0 qrexec source helper. Source refreshes are driven by Qubes-managed state, the qrexec call has a timeout, and the returned rows are filtered to VMs routed through `sys-snitch` before Snitch installs source policy.

Do not report unbounded source-map growth from an untrusted AppVM unless that AppVM can actually create routed Qubes VM identities or arbitrary dom0 helper output.

### PTR names are display hints, not policy truth

PTR names are explicitly shown as `PTR name`, colored as lower-trust hints, and never become nftables match criteria. The actual saved flow rule still matches the concrete destination IP, protocol, and port.

Qubes-Snitch rejects non-ASCII PTR text before display, so Unicode confusable and wide-character PTR findings should not be re-reported unless a PTR display path bypasses the ASCII check.

### Long or odd display text is a UI nit, not a firewall bypass

`safe_text()` removes control/format characters and collapses whitespace before terminal/syslog output. The ASCII truncation marker and module-global pending queue state are not security boundaries. Prompt queue state is RAM-only in the single daemon process, and fail-closed nftables intentionally has no queue rule because Python may not be running yet.

### Local CLI interruption and package pinning are operational issues

Ctrl-C in the local trusted CLI, unpinned apt/Python packages, and installer supply-chain pinning are operational or reproducibility concerns. They are not protected-client-to-firewall bypasses under the current threat model.

### Local CLI socket attacks are out of scope

A local process running as `user` in `sys-snitch` can interfere with the firewall in many trivial ways. Qubes-Snitch intentionally trusts the local `user` and root accounts in the dedicated firewall VM and does not add complexity to defend against that attacker.

### Prompt notification failure is intentionally fail-closed

Prompt and security notifications are part of the firewall UX/security contract. If `notify-send` cannot show required prompt/security visibility, Qubes-Snitch may fail the daemon so systemd leaves fail-closed nftables policy in place.

### Mutable Git install source is accepted installer behavior

The simple dom0 installer clones the current repository into the template and runs `install.sh`. Users are expected to review the cloned repository contents when they need supply-chain review. This is documented and is not treated as a Qubes-Snitch runtime vulnerability.

### Qubes anti-spoofing is intentionally not duplicated in Snitch rules

Qubes owns the per-vif source-IP anti-spoofing layer. Qubes-Snitch requires the relevant Qubes networking/firewall services and only owns its private `table inet qubes_snitch`. Do not report missing `iifname + ip saddr` duplication as a default bug.

Stopping or breaking Qubes firewall/antispoof plumbing is not equivalent to Snitch accepting spoofed traffic: the Qubes services own routing, NAT, DNS DNAT, and antispoofing. Snitch's unit requires the Qubes firewall service chain and the fail-closed table remains when Snitch cannot start.

### Disp-like names are intentionally reserved outside real DispVMs

Qubes-Snitch reserves `disp` in non-DispVM names and `dispvm-*` source names because numbered DispVMs and purpose-specific DispVM policy files use those namespaces. This is a documented naming restriction, not a parser bug. Do not report `validate_qubes_vm_name()` rejecting template/base names containing `disp` as a vulnerability.

### Generic default-DispVM provider rows are intentionally ignored

Generic default disposable policy is temporary and per numbered DispVM. Non-numbered provider rows for the configured default disposable template are ignored so durable policy is not created for broad provider names such as `sys-firewall` or `sys-usb`. This is accepted fail-closed source filtering, not missing source handling.

### IPv6 traffic is intentionally unsupported and blocked

Qubes-Snitch supports IPv4 source identities and `rules4` policy only. Rendered policy accepts/queues IPv4 and the base forward policy is drop. IPv6 behind `sys-snitch` is not a supported traffic path.

### Pending prompts are dropped, not kernel-rejected

When traffic has no saved rule yet, Qubes-Snitch queues a question and must verdict the current packet immediately. It uses the NFQUEUE drop verdict for that current unanswered packet.

Saved reject rules render real nftables rejects. New unanswered prompts are intentionally silent drops until the user answers and a saved rule exists.

### Queued DNS transport drops do not let that query's resolver reply race through

UDP/53 packets from known source VMs are sent to NFQUEUE before resolver/domain handling. If resolver transport has no saved allow yet, the queued packet is still held by NFQUEUE and is then dropped by the daemon. That query never reaches the resolver, so there is no resolver reply for that same packet to race back through established/related rules.

### DNS body policy runs after resolver transport is allowed

Qubes-Snitch treats DNS as two layers: first the VM must have policy allowing UDP/53 transport to the resolver, then Snitch inspects the DNS question/body for domain policy. If resolver transport has no saved allow yet, the packet is queued/dropped as ordinary NET udp/53 traffic and the DNS body is not parsed or classified.

Do not report missing non-ASCII DNS-body alerts before resolver-transport allow as a bypass. The packet is still dropped before reaching the resolver; DNS body inspection starts only after the resolver transport itself is allowed.

### CLI rule saves do not need conntrack flushing

A repeated audit claim says in-place nft reloads from CLI decisions are dangerous because `load_nft()` does not flush conntrack. This mixes up two different workflows.

CLI decisions append a new rule for traffic that had no matching rule. The current packet was already dropped while the daemon waited for the user, so the newly saved allow/reject is not tightening an already-established allowed flow.

Policy tightening is a manual YAML operation: editing, deleting, or reordering existing rules. The supported workflow for manual YAML changes is `systemctl restart qubes-snitchd.service`, and the service runs `conntrack -F` on start. That restart intentionally clears stale established flows after manual policy tightening.

Do not report missing conntrack flushing on CLI allow/reject saves as a bug unless Qubes-Snitch later adds a supported live edit/reorder/delete path for existing rules without service restart.

### Broad established-reply rules are not a standalone bypass

Rendered reply rules for broad allow policy, including `dest: any`, can match broad reply traffic, and the forward chain also has an established/related reply accept for known VM destination IPs. These rules still require conntrack state `established,related` and `ct direction reply`; they do not allow new inbound traffic by themselves.

The only meaningful concern is stale conntrack after manually tightening old broad allow rules. The supported tightening workflow is restarting `qubes-snitchd.service`, and that startup flushes conntrack. Do not report the broad reply rule as a runtime bypass unless Qubes-Snitch later supports live tightening of existing rules without service restart.

### `install-dom0.sh` is not truncated

The installer contains the qrexec service heredoc, qrexec policy heredoc, and later VM setup commands. Do not report a truncated qrexec policy heredoc unless the file actually stops before the policy and VM setup sections.

### Installer package-update ordering is operational and fails safe

The dom0 installer updates the template package index before invoking the in-template install script. If package installation fails, setup aborts before `sys-snitch` is created or configured. Daemon startup also validates required files and loads fail-closed policy before live policy.

Do not report `apt-get install` ordering as a protected-client security bypass unless the installer can leave a running `sys-snitch` with permissive policy after a partial failure.

## Accepted design choices / not planned for removal

### `notify-send` can run while the policy lock is held

Prompt notifications are part of the same user-visible event as queue insertion. A slow desktop notification can briefly delay policy saves and source refreshes, but the effect is bounded by `pending_queue_size` and fails closed.

This is accepted latency, not a bypass. Do not report it as a security issue unless notification work becomes unbounded or starts allowing traffic while the policy is stale.

### Keep synthetic DNS REFUSED for saved DNS rejects

Qubes-Snitch keeps synthetic DNS `REFUSED` replies for saved DNS reject decisions so applications fail fast instead of hanging on resolver timeouts.

This requires raw socket support and `CAP_NET_RAW`, but the original queued DNS query is still dropped. The raw reply path is treated as a small privileged UX feature to keep hardened and tested, not as a feature to remove by default.


