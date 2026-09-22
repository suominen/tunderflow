---
title: "TUNderflow — TUN/TAP receive-headroom underflow"
description: "Linux kernel TUN/TAP receive-headroom integer underflow (CVE-2026-81000, TUNderflow) — out-of-bounds skb head, local privilege escalation to root with a public exploit — distro patch status tracker"
layout: "single"
date: 2026-09-18
lastmod: 2026-09-22
cover:
  image: "tunderflow-tracker.png"
  alt: "TUNderflow — Linux kernel TUN/TAP receive-headroom underflow tracker"
  hiddenInSingle: true
---

## Summary

| Field | Detail |
|---|---|
| CVE ID | CVE-2026-81000 |
| Alias | `TUNderflow` (the name its [PoC][poc] and the [write-up][writeup] use) |
| Component | Kernel: TUN/TAP driver — receive-headroom handling in `tun_set_headroom()` / `tun_get_user()` / `tun_alloc_skb()` (`drivers/net/tun.c`) |
| Type | Integer underflow leading to an out-of-bounds skb head. A receive headroom stored unchecked in `tun->align` makes `SKB_MAX_HEAD(align)` go negative; the value wraps in the `size_t` linear length, and `tun_alloc_skb()` places `skb->data` 64 bytes past the end of a 4,096-byte head, so the packet processing that follows reads and writes outside the allocation |
| Impact | Kernel heap out-of-bounds read/write: a crash (**DoS**) or, with grooming, **local privilege escalation to root** — the public PoC sets `PIPE_BUF_FLAG_CAN_MERGE` on an adjacent pipe buffer and rewrites `/etc/pam.d/su`. Not remotely reachable. A container holding `CAP_NET_ADMIN` over its own network namespace can corrupt the host kernel the same way |
| Upstream fix | [`447c9303942c`][fix] (*net: tun: bound receive headroom*); first in **v7.3-rc1** |
| Introduced | [`eaea34b23c46`][intro] in **v4.6** (2016) — `ndo_set_rx_headroom` support for TUN stored the requested headroom without a bound from the start, so **every TUN-capable kernel from 4.6 on is in-window** |
| Affected window | **4.6 through 7.1** without the backport, and 7.2 before 7.2.4. Fixed in **v7.3-rc1** and the **7.2 / 6.18 / 6.12 / 6.6 / 6.1 / 5.15 / 5.10** stable backports — every maintained upstream line now carries the fix (per-branch *First fixed* below). **7.1.y went end-of-life at 7.1.13 without it.** Distro kernels still need to adopt a fixed release or cherry-pick the fix |
| Discoverer | Asim Viladi Oglu Manizada (`@manizada`) |
| Public disclosure | 2026-09-18 ([oss-security][oss-sec] and the [write-up][writeup]); reported to security@kernel.org in mid-July 2026 and held under a linux-distros@ embargo until the agreed publication date |
| Public PoC | [manizada/TUNderflow][poc] — a working local-root exploit (Python 3), tuned for Fedora 44 and Ubuntu 24.04.4 kernels |
| KEV / EPSS / CVSS | **Kernel CNA:** CVSS 3.1 **7.8 HIGH** (`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`), mirrored by NVD. **Red Hat:** 7.0 (`AC:H`, marked *draft*), severity *Moderate*. Not in KEV; EPSS **0.16%** (6th percentile, scored 2026-09-16 — two days before the exploit went public) |
| Reachability | **TUN/TAP** (`/dev/net/tun`) plus a network-device path that propagates an oversized receive headroom to it — the PoC stacks a **netkit** device under **VXLAN** and an **Open vSwitch** datapath; the CNA also names OVS/veth/VXLAN and bridge/veth/GRETAP loops — all built with **`CAP_NET_ADMIN` inside an attacker-owned network namespace**. Where **unprivileged user namespaces** are enabled (the default on most distributions) any local user has that; where they are disabled the bug needs a container or process that already holds `CAP_NET_ADMIN`. See *Detection* and *Mitigation* |
| Related | [DirtyAH6 (CVE-2026-80844)][dirtyah6], [PPPoEject (CVE-2026-68121)][pppoeject], and [DiagSpill (CVE-2026-74469)][diagspill] — the other three local-root bugs disclosed by the same researcher in the same announcement. Unrelated code paths, reported together and disclosed under one embargo; 7.2.4, 6.18.50, 6.12.109, 6.6.157, 6.1.188, 5.15.221, and 5.10.270 are the first stable releases to carry **all four** fixes — each sibling's own first fix is earlier (see its tracker) |
{.summary}

> :information_source: **One of four.** The announcement covers four
> independent bugs — DirtyAH6 in IPv6 AH (`xfrm`), TUNderflow in TUN/TAP,
> PPPoEject in PPPoE, and DiagSpill in `sctp_diag` — each with its own
> tracker linked above. A kernel build that carries one fix does not
> necessarily carry the others: the four landed as separate commits, and
> a distro cherry-pick can take one without the rest. Check each tracker
> for the kernel you run.

## How the exploitation chain works

TUN and TAP are the virtual network devices that carry packets between
the kernel and a userspace process through `/dev/net/tun`. A device
stacked on top of others can ask the devices below it to reserve extra
**receive headroom** through the `ndo_set_rx_headroom()` callback, and
Open vSwitch carries that request from one port of its datapath to the
others — including a TUN or TAP port. Since [`eaea34b23c46`][intro]
(v4.6, 2016) TUN honours the request by storing it in `tun->align`.

`tun_get_user()`, the write path from userspace into the kernel, uses
`tun->align` for two things: as the headroom to reserve in front of the
packet, and — through `SKB_MAX_HEAD(align)`, the space left in a
one-page skb head after that much headroom — to decide how many bytes of
the packet to keep linear (`good_linear`). Nothing bounded `align` to
what a page can hold. A **netkit** device configured with 4,096 bytes of
headroom, placed under a **VXLAN** device on an **Open vSwitch**
datapath, propagates a 4,160-byte request to a raw TUN port on the same
datapath: `SKB_MAX_HEAD(4160)` underflows, `good_linear` becomes
negative, the value wraps when assigned to the `size_t linear`, and the
`prepad + linear` / `len - linear` arithmetic that follows wraps with it.
`tun_alloc_skb()` then returns an skb whose `skb->data` sits **64 bytes
past the end of its 4,096-byte head**.

Everything downstream of that allocation — the protocol-byte read,
`skb_copy_datagram_from_iter()` copying the attacker's frame, and the
receive processing on the OVS side — now reads and writes relative to a
pointer outside the allocation. The copy is an out-of-bounds **write of
attacker-controlled bytes**, the reads leak kernel memory, and a
misplaced access oopses (`eth_type_trans()` / `__skb_pull()` `BUG()` on
a TAP path, or a plain fault).

The [PoC][poc] turns the write into root the way several recent kernel
LPEs have: it grooms **file-backed pipe buffers** next to the bad TUN
packet's head, uses the Open vSwitch out-of-bounds write to set
`PIPE_BUF_FLAG_CAN_MERGE` on one of them, and then writes through the
pipe into the page cache of `/etc/pam.d/su`, replacing `pam_rootok.so`
with `pam_permit.so`; `su - root` then succeeds without a password. All
of the network setup needs only `CAP_NET_ADMIN` in a network namespace
the attacker owns — which an unprivileged user namespace provides for
free wherever those are enabled.

The fix, [`447c9303942c`][fix], clamps the stored headroom to what a
one-page skb head and a 16-bit header offset can carry
(`min(SKB_MAX_HEAD(0), U16_MAX - 1)`, less one byte for a raw TUN's
protocol byte or a full Ethernet header plus `NET_IP_ALIGN` for TAP),
and makes `tun_get_user()` `pskb_may_pull()` those header bytes before
touching them, so a nonlinear skb from another allocation path stays
safe too.

> :warning: Because the introducing commit landed in **v4.6 (2016)**,
> this is **not** a recent-regression bug: there is no in-support kernel
> old enough to be unaffected. Any kernel with TUN/TAP support, from 4.6
> up to the fixed point releases below, is in-window. A kernel is safe
> only by carrying the [`447c9303942c`][fix] fix — not by being old.

## Vulnerable commit range

| Commit | Role | Description |
|---|---|---|
| [`eaea34b23c46`][intro] | Introduced | *net/tun: implement ndo_set_rx_headroom* (**v4.6**, 2016) — `tun_set_headroom()` stores the requested receive headroom in `tun->align` with only a `NET_SKB_PAD` floor and no ceiling, and `tun_get_user()` sizes the linear part from it. |
| [`447c9303942c`][fix] | Fixed | *net: tun: bound receive headroom* — clamps `tun->align` to the one-page skb-head budget and the largest 16-bit header offset, leaving room for the TUN protocol byte or the TAP Ethernet header, and pulls those bytes before reading them; first released in **v7.3-rc1**. |

The reachable lifetime runs from **v4.6** through **v7.1** (and 7.2
before 7.2.4). No in-support kernel predates the flaw, so the *only*
not-affected kernels are those that carry the fix. The three sibling
bugs have their own, different windows — see their trackers.

## Patch status

A row is **Fixed** only if its kernel carries the [`447c9303942c`][fix]
backport; every TUN-capable kernel from 4.6 on without it is in-window
and **Vulnerable**. The first group is the upstream kernel; the rest are
a focused set of x86-64 distributions, with per-distribution detail in
the sections that follow. *First fixed* and *Fixed since* stay `—` until
a row is fixed.

| Distribution | Release | Current kernel | First fixed | Fixed since | Status |
|---|---|---|---|---|---|
| Linux kernel | mainline | 7.3-rc4 | 7.3-rc1 | 2026-08-30 | :white_check_mark: Fixed — carries `447c9303942c` |
| Linux kernel | 7.2.x | 7.2.7 | 7.2.4 | 2026-09-07 | :white_check_mark: Fixed |
| Linux kernel | 6.18.x | 6.18.53 | 6.18.50 | 2026-09-07 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.12.x | 6.12.111 | 6.12.109 | 2026-09-07 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.6.x | 6.6.157 | 6.6.157 | 2026-09-14 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.1.x | 6.1.188 | 6.1.188 | 2026-09-14 | :white_check_mark: Fixed — LTS |
| Linux kernel | 5.15.x | 5.15.221 | 5.15.221 | 2026-09-14 | :white_check_mark: Fixed — LTS |
| Linux kernel | 5.10.x | 5.10.270 | 5.10.270 | 2026-09-14 | :white_check_mark: Fixed — LTS |
| Debian | sid (unstable) | 7.2.6-1 | 7.2.6-1 | 2026-09-17 | :white_check_mark: Fixed |
| Debian | forky (testing) | 7.1.13-1 | — | — | :x: Vulnerable — 7.1.y EOL |
| Debian | 13 (trixie) | 6.12.107-1 | — | — | :x: Vulnerable |
| Debian | 12 (bookworm) | 6.1.187-1 | — | — | :x: Vulnerable |
| Debian | 12 (6.12 opt-in) | 6.12.107-1~deb12u1 | — | — | :x: Vulnerable |
| Proxmox VE | 9 (default) | 7.0.14-19-pve | 7.0.14-19 | 2026-09-18 | :white_check_mark: Fixed |
| NixOS | master | 6.18.53 | 6.18.50 | 2026-09-07 | :white_check_mark: Fixed |
| NixOS | release-26.05 | 6.18.53 | 6.18.50 | 2026-09-07 | :white_check_mark: Fixed |
| NixOS | Unstable | 6.18.53 | 6.18.50 | 2026-09-08 | :white_check_mark: Fixed |
| NixOS | Unstable (small) | 6.18.52 | 6.18.50 | 2026-09-08 | :white_check_mark: Fixed |
| NixOS | Unstable (nixpkgs) | 6.18.52 | 6.18.50 | 2026-09-08 | :white_check_mark: Fixed |
| NixOS | 26.05 | 6.18.52 | 6.18.50 | 2026-09-09 | :white_check_mark: Fixed |
| NixOS | 26.05 (small) | 6.18.52 | 6.18.50 | 2026-09-08 | :white_check_mark: Fixed |
| Rocky Linux / RHEL | 10 | 6.12.0-211.56.1.el10_2.0.1 | — | — | :x: Vulnerable — no RHSA yet |
| Rocky Linux / RHEL | 9 | 5.14.0-687.49.1.el9_8 | — | — | :x: Vulnerable — no RHSA yet |
| Rocky Linux / RHEL | 8 | 4.18.0-553.164.1.el8_10 | — | — | :x: Vulnerable — no RHSA yet |
| Amazon Linux | 2023 (default) | 6.1.186-228.376 | — | — | :x: Vulnerable — no ALAS yet |
| Amazon Linux | 2023 (6.12 opt-in) | 6.12.103-129.197 | — | — | :x: Vulnerable — no ALAS yet |
| Amazon Linux | 2023 (6.18 opt-in) | 6.18.48-109.150 | — | — | :x: Vulnerable — no ALAS yet |
{.distros}

### Linux kernel

The fix reached Linus in **v7.3-rc1** (tagged 2026-08-30), through the
netdev tree, some six weeks after the mid-July report. The stable
backports landed in two rounds. On **2026-09-07** the **7.2.4**
(`0ada54ea63e4`), **6.18.50** (`e098d9cc8859`), and **6.12.109**
(`379d85c7f25f`) releases picked it up; on **2026-09-14** the
**6.6.157** (`010eee265d6b`), **6.1.188** (`18ef24cdb2eb`),
**5.15.221** (`708e87937de9`), and **5.10.270** (`ad715e713610`)
releases followed — each the same fix by subject, confirmed present on
its `linux-*.y` branch. Every maintained upstream kernel line now
carries the fix; these releases are also the first to carry all four of
the announcement's fixes.

**7.1.y never received it.** The 7.1 line reached end of life at
**7.1.13** (per `kernel.org`'s `finger_banner`) before the backport was
queued, so every 7.1 release is permanently vulnerable: a host on a 7.1
kernel has no fix coming on that line and needs to move to 7.2 or to a
longterm branch. Debian's testing suite currently rides it — see
*Debian*.

To check a tree directly: a fixed `tun_set_headroom()` (in
`drivers/net/tun.c`) computes a `max_headroom` from `SKB_MAX_HEAD(0)`
and `U16_MAX - 1` and stores `tun->align` through `clamp_t()`; an
unfixed one assigns the requested value after only a `NET_SKB_PAD`
floor.

### Debian

Debian's status splits on which upstream branch each suite tracks.
**sid** is **fixed** since the `7.2.6-1` upload — the first Debian
kernel past the 7.2 branch's `7.2.4` first fix (sid went straight from
7.1.13 to 7.2.6). **forky** (testing, the future Debian 14) is still on
the **7.1** line, which went end-of-life upstream at 7.1.13 without the
fix: no 7.1 upload can close it, so forky becomes fixed only when the
7.2 kernel migrates from sid. **trixie** (Debian 13) rides 6.12 and its
`trixie-security` kernel predates the branch's `6.12.109` first fix;
**bookworm** (Debian 12) rides 6.1 and its `bookworm-security` kernel
stops one point release short of the `6.1.188` first fix. The security
tracker lists both as *open*. Debian may close the gap by rebasing onto
the fixed point release or with a `-security` upload that cherry-picks
the fix into a build numbered below it — so the security tracker, not
the version number, says when a suite is fixed.

bookworm also offers an **opt-in newer kernel**, the `linux-6.12`
source package in `bookworm-security` (trixie's kernel rebuilt for
bookworm). Its current build also predates `6.12.109`, and the security
tracker carries no `linux-6.12` entry for this CVE yet, so it is
**vulnerable** like the default.

**bullseye (Debian 11) reached the end of its LTS support window on
2026-08-31**, before this bug was disclosed, so it will never receive
the fix: both its 5.10-line default kernel and the former `linux-6.1`
opt-in are permanently **vulnerable**. A host still on bullseye should
upgrade to bookworm or newer.

Debian's stock kernels meet the bug's pre-requisites: `tun`,
`openvswitch`, and `vxlan` ship as modules, netkit is built in
(`CONFIG_NETKIT=y`), and unprivileged user namespaces are enabled by
default (`kernel.unprivileged_userns_clone = 1`).

### Proxmox VE

Proxmox ships its own Ubuntu-derived kernels, so Debian's status does
not carry over. **PVE 9** is **fixed**: `proxmox-kernel-7.0` picked up
a named cherry-pick in the `7.0.14-19` changelog entry, dated
2026-09-18, and that build has since reached `pve-no-subscription`.

**PVE 8** reached end of life in **August 2026**, before this tracker
existed and before any fix reached its kernels: its default
`proxmox-kernel-6.8` and the `bookworm-backports` opt-in
`proxmox-kernel-6.14` are permanently **vulnerable**, and no fix is
coming. A host still on PVE 8 should upgrade to PVE 9.

PVE 9 also still publishes preview kernel series that Proxmox stopped
updating before this disclosure and that will never receive the fix:
`proxmox-kernel-6.17` (last built July 2026) and `-6.14` (May 2026). A
host booting either of them stays vulnerable until it switches to the
current default kernel, which carries the fix.

Proxmox hosts are also where TUN/TAP and Open vSwitch are routinely in
use: every VM's network interface is a TAP device, and
`openvswitch-switch` is a supported bridge backend. That does not widen
*who* can trigger the bug — the attacker still needs `CAP_NET_ADMIN`
over a network namespace — but two audiences are in scope: an
unprivileged LXC container is exactly such a namespace, and an ordinary
shell account on the host has one wherever unprivileged user namespaces
are enabled, which is the default in the Ubuntu kernels PVE builds from.
Check the host with the *Detection* commands rather than assuming either
way.

### NixOS

Every tracked ref's default `linuxPackages` is `linux_6_18`, at or above
the 6.18 branch's `6.18.50` first-fixed release, so every tracked ref is
**fixed**; they differ only in when each first published that bump.
Kernel updates land on nixpkgs `master` first, and each channel
publishes them once its Hydra jobset passes. A channel can therefore sit
a few days behind `master`, and an unstable channel is not necessarily
ahead of a release channel. The `-small` channels
(`nixos-unstable-small`, `nixos-26.05-small`) are gated on a reduced
jobset and pick up kernel updates fastest. nixpkgs also pins the older
longterm series (`linux_6_12`, `linux_6_6`, `linux_6_1`, `linux_5_15`,
`linux_5_10`) at or above their branches' first fix on every tracked
ref, so a host overriding the default to one of them is fixed as well —
as long as it tracks a ref current enough to have picked up the
mid-September bumps.

The `master` and `release-26.05` rows are the git branches the fix lands
on. They are not Hydra-gated, so they carry a kernel bump from the
moment the commit lands — typically a day or more before a channel
republishes it, which is what the *Fixed since* dates down the group
show. They are development branches, not deployment targets.

Flake inputs map onto these directly.
`github:NixOS/nixpkgs/nixos-unstable` tracks the `nixos-unstable`
channel — the GitHub channel branches are updated to exactly the
published channel pins — and a bare `github:NixOS/nixpkgs` with no ref
follows `master`. A bare `nixpkgs` registry input resolves by default to
`nixpkgs-unstable`, which is a separate channel aimed at Nix users on
other operating systems rather than at NixOS, so it is not gated on the
NixOS tests and can hold a different kernel from `nixos-unstable`.

### Rocky Linux / RHEL family

RHEL-family kernels are long-lived forks; all three in-support lines —
EL10 (6.12-based), EL9 (5.14-based), EL8 (4.18-based) — postdate the
v4.6 introduction and carry TUN/TAP, so all are in-window. Red Hat's
security data (record public since 2026-09-11) marks the `kernel` and
`kernel-rt` packages **Affected** for RHEL 7, 8, 9, and 10 with no fixed
release and no RHSA yet (RHEL 6 is out of support scope), so every
stream is **vulnerable pending an advisory**. Red Hat's own draft score
is 7.0 with severity *Moderate* — it rates the attack complexity high —
which usually means the fix rides a regular batch kernel update rather
than an out-of-cycle one. The `kernel-rt` real-time variant is listed
Affected alongside the standard kernel and will be fixed by the same
advisories. Rocky rebuilds RHEL's kernels unchanged, so its fixes track
Red Hat's; AlmaLinux is typically the fastest rebuild and the leading
indicator. Oracle Linux and CloudLinux track the RHEL determination.

### Amazon Linux

All three AL2023 kernel streams are **vulnerable**: the default `kernel`
package (6.1 line) and the opt-in `kernel6.12` and `kernel6.18` streams
all ship builds below their branches' first fix (6.1.188, 6.12.109, and
6.18.50), and the repodata's `updateinfo.xml` names no ALAS for this CVE
yet. Amazon often backports a fix into a build *below* the upstream
threshold, so only an ALAS confirms a fix — and the CVE-to-advisory
mapping can trail the advisory itself by weeks in the published repodata.

**Amazon Linux 2 reached end of support on 2026-06-30**, before this bug
was disclosed, so none of its kernel streams will receive the fix: every
AL2 kernel from 4.14 on is in-window and permanently **vulnerable**. A
host still on AL2 should migrate to AL2023.

## Detection

**Is the running kernel in the affected window and missing the fix?**
Every TUN-capable kernel from 4.6 on is in-window; compare the running
kernel against the *Patch status* table's *First fixed* column for its
series (distro builds below that number can still carry a cherry-pick —
the table's *Status* is the verdict):

```bash
uname -r
```

**Is TUN/TAP available?**  The bug needs `/dev/net/tun`. Almost every
distribution ships it as the `tun` module, autoloaded when anything
opens the device node — VPN clients, QEMU/libvirt, and container
runtimes all do:

```bash
ls -l /dev/net/tun
```

**Are the headroom-propagating modules loaded?**  The public exploit
needs Open vSwitch, VXLAN, and netkit on top of TUN. netkit is built
into the kernel wherever it is enabled (`CONFIG_NETKIT` cannot be a
module), so only the other three can show up here; a loaded module
means the path is already in use, and an unloaded one is not safety,
since an unprivileged network namespace can trigger its autoload:

```bash
lsmod | grep -E '^(tun|openvswitch|vxlan) '
```

**Can an ordinary user create user namespaces?**  Where they can, every
local user has the `CAP_NET_ADMIN` the bug needs. `user.max_user_namespaces`
is the generic knob (`0` disables); Debian adds
`kernel.unprivileged_userns_clone`, and Ubuntu 24.04 and later restrict
unprivileged namespaces through AppArmor
(`kernel.apparmor_restrict_unprivileged_userns`):

```bash
sysctl user.max_user_namespaces kernel.unprivileged_userns_clone kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
```

## Public PoC

The upstream PoC is in [manizada/TUNderflow][poc]: a Python 3 script
that builds the netkit/VXLAN/Open vSwitch topology in a private user and
network namespace, grooms 4 KiB skb heads next to pipe rings holding a
buffer from `/etc/pam.d/su`, sends the crafted TUN packets, and then
writes `pam_permit.so` through the merged pipe before running
`su - root`. It is tuned for two targets — Fedora 44 with
`6.19.10-300.fc44.x86_64` and Ubuntu 24.04.4 with
`6.17.0-40-generic` — and the author notes that other kernels need their
own grooming parameters, that a misplaced overwrite can hang or crash
the host, and that the exploit **modifies `/etc/pam.d/su` without
rollback**. Do **not** run it on a system you are not authorised to
test, and only in a disposable VM.

## Mitigation

The real fix is a patched kernel (the [`447c9303942c`][fix] backport).
Until one is installed, the exposure is narrowed by taking away the
capability or the device path the bug needs — none of these is a fix,
and the researcher explicitly warns that blocking only the PoC's modules
leaves other paths to the same bug.

### Disable unprivileged user namespaces

This removes the ordinary-user path to TUNderflow (and to DirtyAH6 and
PPPoEject) on a multi-user host. It does nothing against a container or
process that already holds `CAP_NET_ADMIN`, and it breaks software that
relies on user namespaces — rootless container runtimes, Flatpak,
browser sandboxes — so test before rolling it out. The generic knob
(persist it in `/etc/sysctl.d/`):

```bash
sudo sysctl -w user.max_user_namespaces=0
```

On Debian the dedicated switch is preferable, since it leaves namespaces
available to root:

```bash
sudo sysctl -w kernel.unprivileged_userns_clone=0
```

### Block the `tun` module (if you don't use TUN/TAP)

Where nothing on the host uses TUN/TAP — no VPN client, no VM or
container networking through tap devices — block the module so the
vulnerable code cannot be loaded; `install tun /bin/false` is surer than
a plain `blacklist tun`, which only suppresses alias-based autoloading:

```bash
echo 'install tun /bin/false' | sudo tee /etc/modprobe.d/tunderflow.conf
```

Blocking `openvswitch` the same way cuts the propagation path the public
exploit uses, but the CNA lists bridge/veth/GRETAP loops as alternative
paths, so treat that as a speed bump rather than a mitigation.

## Risk notes

- **A working exploit has been public since disclosure day.** Unlike
  many kernel CVEs, this one arrived with a tested local-root PoC for
  two mainstream distributions and a detailed write-up; adapting it to
  another kernel is grooming work, not research. Treat every in-window
  multi-user or container host as exploitable now.
- **No kernel is too old to be affected.** The bug dates from v4.6
  (2016). Every in-support distribution kernel, including the
  RHEL 8 4.18 line and the Amazon Linux 6.1 line, is in-window and
  unsafe until it carries the backport.
- **Backports available (CVE-2026-81000):** the fix has landed in
  7.3-rc1, 7.2.4, 6.18.50, 6.12.109, 6.6.157, 6.1.188, 5.15.221, and
  5.10.270; distro kernels that have not adopted one of those, or
  cherry-picked `447c9303942c`, remain vulnerable. The 7.1.y line is
  end-of-life without it.

## Verification log

Every verdict in the table above is backed by a checkable source. This
log records the provenance — the advisory, repository index, or git
reference that established each fact — so any row can be audited or
reproduced. Most readers never need it.

{{< details summary="Full verification log" >}}
#### Upstream

- **Fix commit** (via `git show` in `~/src/linux/stable`):
  - `447c9303942c439a117d9b76ce6d6e2116b38ee7` — *net: tun: bound
    receive headroom*.
  - Authored 2026-08-12 by the discoverer; `Reviewed-by` Willem de
    Bruijn; applied by Jakub Kicinski.
  - Touches `drivers/net/tun.c` only.
  - Carries `Fixes: eaea34b23c46` and `Cc: stable@vger.kernel.org`.
  - `git describe --contains` → `v7.3-rc1~133^2^2~40`.
- **Introducing commit** (via `git show` in `~/src/linux/stable`):
  - `eaea34b23c46bf17b4a5638be69ab3561854f34b` — *net/tun: implement
    ndo_set_rx_headroom*, 2016-02-26.
  - `git describe --contains` → `v4.6-rc1~91^2~164^2~1`; `v4.6` tagged
    2016-05-15.
- **Release tag dates** (via `git log -1 --format=%cd <tag>` in
  `~/src/linux/stable`):
  - `v7.3-rc1` — 2026-08-30.
  - `v7.2.4`, `v6.18.50`, `v6.12.109` — 2026-09-07.
  - `v6.6.157`, `v6.1.188`, `v5.15.221`, `v5.10.270` — 2026-09-14.
- **Stable backports** (via `git log origin/linux-<series>.y
  --grep=447c9303942c --grep='bound receive headroom'` in
  `~/src/linux/stable`; one hit per branch, each with the fix's own
  subject):
  - 7.2.y — `0ada54ea63e4`.
  - 6.18.y — `e098d9cc8859`.
  - 6.12.y — `379d85c7f25f`.
  - 6.6.y — `010eee265d6b`.
  - 6.1.y — `18ef24cdb2eb`.
  - 5.15.y — `708e87937de9`.
  - 5.10.y — `ad715e713610`.
  - 7.1.y — no hit; the branch's last tag is `v7.1.13` and
    `finger_banner` lists 7.1 as EOL, so the line ended without the fix.
- **Current point releases** (via `https://www.kernel.org/finger_banner`):
  - *Current kernel* for every `Linux kernel` row is read from the
    banner's per-series line.
- **CVE record** (via `git show origin/master:cve/published/2026/CVE-2026-81000.{dyad,json,cvss}`
  in `~/src/linux/vulns`):
  - The dyad holds eight `4.6:eaea34b23c46:<fixed>` pairs — 7.3-rc1,
    7.2.4, 6.18.50, 6.12.109, 6.6.157, 6.1.188, 5.15.221, 5.10.270 —
    matching the backports above.
  - The `.json` lists `drivers/net/tun.c` as the only affected file.
  - The `.cvss` file scores CVSS 3.1 7.8
    (`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`).
  - Its rationale names the netkit `IFLA_NETKIT_HEADROOM`,
    OVS/veth/VXLAN, and bridge/veth/GRETAP headroom paths.
- **Scores and lists** (via the NVD 2.0 API, Red Hat's hydra
  `securitydata` JSON, the FIRST EPSS API, and the CISA KEV feed):
  - NVD published the record 2026-09-11; its only metric is the CNA's
    7.8 vector.
  - Red Hat: `cvss3_base_score` 7.0
    (`AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`), status `draft`.
  - Red Hat `threat_severity`: Moderate.
  - EPSS 0.00164 (percentile 0.0599), scored 2026-09-16.
  - Not present in the KEV catalogue.
- **Disclosure** (via the oss-security archive, the researcher's
  write-up, and the PoC README):
  - oss-security message 2026/09/18/3, dated 2026-09-18 06:15 UTC,
    covers all four bugs and names the four fixing commits.
  - The message's per-branch affected ranges for TUNderflow match the
    dyad.
  - The write-up dates the report to security@kernel.org to mid-July
    2026 and the agreed publication to 2026-09-18 06:00 UTC.
  - The PoC README names its targets (Fedora 44 `6.19.10-300.fc44`,
    Ubuntu 24.04.4 `6.17.0-40-generic`), its module and namespace
    pre-requisites, and the `/etc/pam.d/su` rewrite.
- **Kernel configuration** (via `drivers/net/Kconfig` in
  `~/src/linux/stable`):
  - `CONFIG_NETKIT` is a `bool` option, so netkit is never a loadable
    module.

#### Distributions

- **Debian** (via the security tracker JSON, the dak madison API, and
  snapshot.debian.org):
  - Tracker: `sid` *resolved*, fixed version `7.2.6-1`.
  - Tracker: `forky`, `trixie`, and `bookworm` *open*.
  - Tracker: no `bullseye` entry (LTS ended 2026-08-31).
  - Tracker: no `linux-6.12` entry.
  - sid *Fixed since*: `first_seen` of the `7.2.6-1` source files on
    snapshot.debian.org, 2026-09-17T02:27:04Z.
  - *Current kernel* per suite is the madison version of `linux` in
    `sid`, `forky`, `trixie`/`trixie-security`, and
    `bookworm`/`bookworm-security` — the `-security` version where one
    exists — and of `linux-6.12` in `bookworm-security` for the opt-in
    row.
  - forky's kernel is the 7.1 line, which upstream ended at 7.1.13
    without the fix.
- **Proxmox VE** (via `pve-no-subscription` `Packages.gz` for `trixie`,
  the `~/src/proxmox/pve-kernel` changelogs, and Ubuntu's CVE JSON):
  - `proxmox-default-kernel` depends on `proxmox-kernel-7.0` on trixie.
  - *Current kernel* is the highest `proxmox-kernel-<series>`
    metapackage version in that index.
  - `debian/changelog` on `origin/master` (7.0) carries the fix in the
    `7.0.14-19` entry ("fix CVE-2026-81000: net: tun: bound receive
    headroom"), dated 2026-09-18; `pve-no-subscription` now publishes
    that build.
  - PVE 8 reached end of life in 2026-08 (Proxmox VE FAQ lifecycle
    table, pve.proxmox.com/wiki/FAQ), before this tracker existed.
  - `origin/bookworm-6.8` carried no CVE-2026-81000 or TUN headroom
    cherry-pick at its final build.
  - Ubuntu's tracker marks the 6.8 base *needed*.
  - Series last updated before the disclosure, without the fix:
    trixie `proxmox-kernel-6.17` (changelog head 2026-07-28) and
    `-6.14` (2026-05-15).
- **NixOS** (via `channels.nixos.org/<channel>/git-revision` →
  `pkgs/os-specific/linux/kernel/kernels-org.json` in
  `~/src/nixos/nixpkgs`, `packageAliases.linux_default` in
  `pkgs/top-level/linux-kernels.nix`, and `scripts/nixos-first-shipped`):
  - `linux_default` is `linux_6_18` on both `master` and
    `release-26.05`.
  - The `linux_6_18: 6.18.49 -> 6.18.50` bump is `10d202d8cd13` on
    `master`, committed 2026-09-07.
  - The same bump is `7098dd935667` on `release-26.05`, committed
    2026-09-07.
  - First channel release containing the bump: `nixos-unstable`,
    `nixos-unstable-small`, `nixpkgs-unstable`, and `nixos-26.05-small`
    on 2026-09-08.
  - First channel release containing the bump: `nixos-26.05` on
    2026-09-09.
  - *Current kernel* per row is the `6.18` entry of `kernels-org.json`
    at that ref.
  - The 6.12, 6.6, 6.1, 5.15, and 5.10 entries at every tracked ref
    are at or above their branches' first-fixed releases.
- **Rocky Linux / RHEL** (via Red Hat's hydra `securitydata` JSON and
  the Rocky BaseOS `x86_64` `primary.xml.gz`):
  - `package_state`: `kernel` and `kernel-rt` *Affected* on RHEL 7, 8,
    9, and 10.
  - `package_state`: RHEL 6 *Out of support scope*.
  - `affected_release` is empty — no RHSA.
  - *Current kernel* per release is the highest `kernel` `ver`/`rel`
    in `primary.xml.gz`, compared by RPM rules — a release with more
    numeric segments sorts above `553.el8_10`, so a plain `sort -V` on
    the raw attribute misorders EL8.
- **Amazon Linux** (via `cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list`
  → `primary.xml.gz` and `updateinfo.xml.gz`, the latter parsed with
  `scripts/alas-cve`):
  - Streams present: `kernel` (6.1 line), `kernel6.12`, `kernel6.18`.
  - *Current kernel* is the highest `ver-rel` per stream.
  - `alas-cve CVE-2026-81000` exits 1 — no advisory names the CVE yet.
  - AL2 excluded — end of support 2026-06-30.
{{< /details >}}

## References

| Source | URL |
|---|---|
| Public PoC | <https://github.com/manizada/TUNderflow> |
| Disclosure write-up | <https://heyitsas.im/posts/lpe-quartet/> |
| oss-security announcement | <https://www.openwall.com/lists/oss-security/2026/09/18/3> |
| Kernel fix | <https://github.com/torvalds/linux/commit/447c9303942c439a117d9b76ce6d6e2116b38ee7> |
| Introducing commit | <https://github.com/torvalds/linux/commit/eaea34b23c46bf17b4a5638be69ab3561854f34b> |
| CVE-2026-81000 | <https://www.cve.org/CVERecord?id=CVE-2026-81000> |
| Sibling tracker — DirtyAH6 | <https://kimmo.cloud/dirtyah6/> |
| Sibling tracker — PPPoEject | <https://kimmo.cloud/pppoeject/> |
| Sibling tracker — DiagSpill | <https://kimmo.cloud/diagspill/> |
| stable point release banner | <https://www.kernel.org/finger_banner> |
| Debian security tracker | <https://security-tracker.debian.org/tracker/CVE-2026-81000> |
| Debian package madison (dak-backed) | <https://api.ftp-master.debian.org/madison?package=linux&s=sid,forky,trixie,bookworm&text=on> |
| Ubuntu security tracker | <https://ubuntu.com/security/CVE-2026-81000> |
| Red Hat CVE page | <https://access.redhat.com/security/cve/CVE-2026-81000> |
| AlmaLinux errata | <https://errata.almalinux.org/> |
| Amazon Linux ALAS | <https://alas.aws.amazon.com/> |
{.references}

[poc]: https://github.com/manizada/TUNderflow
[writeup]: https://heyitsas.im/posts/lpe-quartet/
[oss-sec]: https://www.openwall.com/lists/oss-security/2026/09/18/3
[fix]: https://github.com/torvalds/linux/commit/447c9303942c439a117d9b76ce6d6e2116b38ee7
[intro]: https://github.com/torvalds/linux/commit/eaea34b23c46bf17b4a5638be69ab3561854f34b
[dirtyah6]: https://kimmo.cloud/dirtyah6/
[pppoeject]: https://kimmo.cloud/pppoeject/
[diagspill]: https://kimmo.cloud/diagspill/
