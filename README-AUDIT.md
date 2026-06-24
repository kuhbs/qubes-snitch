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

### Unicode confusable DNS names are not accepted by the live qname regex

Python `re` character ranges such as `[a-z]` do not match Cyrillic/CJK characters. Live DNS qnames are restricted by ASCII-range regexes and additional checks that reject punycode/IDN labels.

### PTR names are display hints, not policy truth

PTR names are explicitly shown as `PTR name`, colored as lower-trust hints, and never become nftables match criteria. A misleading PTR, confusable PTR text, or long PTR display can at most influence user judgment; it is not a code bypass. The actual saved flow rule still matches the concrete destination IP, protocol, and port.

### Long or odd display text is a UI nit, not a firewall bypass

`safe_text()` removes control/format characters and collapses whitespace before terminal/syslog output. The Unicode ellipsis used for truncation and module-global pending queue state are not security boundaries. Prompt queue state is RAM-only in the single daemon process, and fail-closed nftables intentionally has no queue rule because Python may not be running yet.

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

### CLI rule saves do not need conntrack flushing

A repeated audit claim says in-place nft reloads from CLI decisions are dangerous because `load_nft()` does not flush conntrack. This mixes up two different workflows.

CLI decisions append a new rule for traffic that had no matching rule. The current packet was already dropped while the daemon waited for the user, so the newly saved allow/reject is not tightening an already-established allowed flow.

Policy tightening is a manual YAML operation: editing, deleting, or reordering existing rules. The supported workflow for manual YAML changes is `systemctl restart qubes-snitchd.service`, and the service runs `conntrack -F` on start. That restart intentionally clears stale established flows after manual policy tightening.

Do not report missing conntrack flushing on CLI allow/reject saves as a bug unless Qubes-Snitch later adds a supported live edit/reorder/delete path for existing rules without service restart.

### Broad established-reply rules are not a standalone bypass

Rendered reply rules for broad allow policy, including `dest: any`, can match broad reply traffic, and the forward chain also has an established/related reply accept for known VM destination IPs. These rules still require conntrack state `established,related` and `ct direction reply`; they do not allow new inbound traffic by themselves.

The only meaningful concern is stale conntrack after manually tightening old broad allow rules. The supported tightening workflow is restarting `qubes-snitchd.service`, and that startup flushes conntrack. Do not report the broad reply rule as a runtime bypass unless Qubes-Snitch later supports live tightening of existing rules without service restart.

### The current `install-dom0.sh` is not truncated

If an audit claims the qrexec policy heredoc is truncated, re-check the current repository. The current installer contains the qrexec service heredoc, qrexec policy heredoc, and later VM setup commands.

## Accepted design choices / not planned for removal

### Keep synthetic DNS REFUSED for saved DNS rejects

Qubes-Snitch keeps synthetic DNS `REFUSED` replies for saved DNS reject decisions so applications fail fast instead of hanging on resolver timeouts.

This requires raw socket support and `CAP_NET_RAW`, but the original queued DNS query is still dropped. The raw reply path is treated as a small privileged UX feature to keep hardened and tested, not as a feature to remove by default.


