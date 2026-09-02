# Third-party software and Lynis review

This file records a factual dependency and attribution review for this
repository. It is not legal advice. Distribution, licensing, trademark, and
contract questions for a particular release should be reviewed by the project
owner or qualified counsel.

## Scope and outcome

Review date: 2026-09-02. The review covers tracked source, documentation, CI,
installer code, test fixtures, and repository assets.

| Item | Repository treatment | Result |
| --- | --- | --- |
| Lynis Community/Client | Detected, installed from configured APT repositories, and invoked on the target host. | External runtime dependency; not redistributed by this repository. |
| Lynis Enterprise | Not installed, called, bundled, or configured. | Not included. |
| Lynis plugins | Not installed, called, bundled, or configured. | Not included; evaluate separately before any future use. |
| Lynis source, profile database, binaries, packages, tarballs, reports, screenshots, and logos | Not tracked or shipped. | Not redistributed. |

The tool may run `lynis audit system` and a narrowly scoped `lynis show details`
command after Lynis is supplied by the target system's configured package
repositories. CI and the installer do not download, vendor, embed, modify, or
redistribute Lynis. Generated reports are created on the target host and are
not repository artifacts.

This repository contains only short command names, test IDs, parser patterns,
and synthetic parser fixtures. The fixtures are deliberately invented minimal
data used to test this project's parser; they are not copied Lynis reports or
control descriptions. Guidance about findings is project-authored paraphrase.

## Lynis sources and factual conclusions

| Authoritative source | Observed fact | Repository conclusion |
| --- | --- | --- |
| [CISOfy/Lynis 3.1.6 release](https://github.com/CISOfy/lynis/releases/tag/3.1.6) | CISOfy publishes the 3.1.6 release from its official repository. | The version reference in this repository is a reference to an external upstream release, not a copy of it. |
| [Lynis 3.1.6 LICENSE](https://raw.githubusercontent.com/CISOfy/lynis/3.1.6/LICENSE) | The tagged upstream LICENSE is GNU GPL version 3. | Do not infer a project license from this external tool. No GPL text is copied here because Lynis itself is not redistributed. |
| [CISOfy legal notices](https://cisofy.com/legal/) | CISOfy states that GPLv3 applies to Lynis Community and Client, while Enterprise offerings have separate EULA or service terms. | Community/Client and Enterprise must not be treated as the same offer. This repository includes no Enterprise material or Enterprise-specific configuration. |
| [CISOfy downloads](https://cisofy.com/downloads/) | CISOfy lists Lynis plugins separately and describes their licensing as potentially open-source or commercial. | A future plugin addition requires a separate package, license, and attribution review. |
| [Lynis Enterprise EULA](https://cisofy.com/static/cisofy-eula.pdf) | CISOfy publishes a separate Enterprise EULA. | Enterprise terms are outside this repository's scope and are not adopted here. |

## Attribution, independence, and release controls

Lynis is an external CISOfy product. This project is independent of CISOfy and
is neither affiliated with nor endorsed by CISOfy. It does not use CISOfy or
Lynis logos and does not make product-compatibility, partnership, certification,
or endorsement claims.

The project's own license remains unselected. That unresolved project-level
release decision is distinct from the GPLv3 status of external Lynis
Community/Client software. This document grants no rights in this repository
and does not select a license for it.

Before a release that adds any third-party material, re-run this inventory and
review the applicable upstream license, notice, source-offer, attribution,
contract, and trademark requirements for the exact material being distributed.

## Deliberate limits and open questions

- This is a technical inventory, not a legal determination of copyright,
  trademark, or GPL obligations.
- The legal status of a particular captured Lynis output depends on its content
  and intended distribution. The repository does not publish such output.
- CISOfy/Lynis names are used only for accurate identification and source links.
  Any promotional, commercial, logo, screenshot, or stronger branding use needs
  separate trademark review.
- A future change that vendors, patches, downloads, ships, or enables Lynis
  plugins requires a new third-party review before release.
