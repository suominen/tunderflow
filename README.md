# TUNderflow — Linux kernel TUN/TAP receive-headroom underflow tracking site

Source for the **TUNderflow** patch-status tracker: a single-page site
recording which distributions have shipped a fix for
a Linux kernel TUN/TAP out-of-bounds bug exploitable for local
privilege escalation.

## Where the facts live

Everything about the bug — CVE IDs, affected and fixed versions, upstream
fix commits, discovery and disclosure credit, and current per-distribution
patch status — belongs to the tracker page, not to this README:

- **Rendered:** <https://kimmo.cloud/tunderflow/>
- **Source:** [`site/content/_index.md`](site/content/_index.md)

Edit that file; everything else in this repo is build infrastructure.

None of it is restated here on purpose.  The tracker page is revised as
CVEs are assigned and distributions ship fixes — twice daily by the
auto-update agent while the tracker is live — so any copy kept in this
README would silently rot.  Resist re-adding a summary.

Deployment plan and current setup state live in [`WEBSITE.md`](WEBSITE.md).

## Local development

Requires Hugo ≥ 0.146.0 (the standard edition suffices: no Sass or image
processing in this site) and Go (for Hugo Modules to fetch the PaperMod
theme).

```sh
nix develop          # dev shell: hugo, go, resvg + fonts, and every lookup tool
cd site
hugo server          # local preview at http://localhost:1313/tunderflow/
```

If you use [direnv](https://direnv.net/), `direnv allow` once and the dev
shell auto-activates whenever you `cd` into the repo.

## Build and publish

```sh
make build       # local build into site/public/
make dist        # build, then rsync to haig:/tunderflow/
make banner      # re-rasterise the social banner SVG → PNG (needs resvg + the banner fonts)
```

`make dist` runs `make build` first. `make banner` is only needed after
editing `site/assets/tunderflow-tracker.svg`; the rendered PNG is committed.

## License

[CC BY 4.0](LICENSE) — share and adapt with attribution.
