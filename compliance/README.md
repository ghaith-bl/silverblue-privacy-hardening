# compliance

OpenSCAP, both ways: the plain profile and the profile tailored to this setup.

- Content: scap-security-guide 0.1.82, `ssg-fedora-ds.xml`, profile `cis_workstation_l2`
  (DRAFT, based on the CIS Fedora community branch). Scanner: openscap 1.4.6.
- `tailoring.xml`: the profile without my deviations (unselected) and with my values where
  the profile has a variable for them (`set-value`). Reason and review date of every entry:
  [docs/deviations.md](../docs/deviations.md), column Tailoring; `tests/test_tailoring.py`
  checks both files against each other. Backlog rules stay in: they fail until fixed.
- Results: both counts, failing ids by kind, no host data: `scan-summary.md` (after each
  scan). Reports stay on the host (`.gitignore`: `scap-*`): they hold host names,
  addresses, package lists.

## Scan

As root (some checks read root-only files), from the repo folder. Exit code 2 = at least
one rule failed, not an error.

```bash
DS=/usr/share/xml/scap/ssg/content/ssg-fedora-ds.xml
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_workstation_l2 \
  --results scap-plain.xml --report scap-plain.html "$DS"
sudo oscap xccdf eval --tailoring-file compliance/tailoring.xml \
  --profile xccdf_org.ssgproject.content_profile_cis_workstation_l2_tailored \
  --results scap-tailored.xml --report scap-tailored.html "$DS"
```

Never `--remediate` (server-oriented fixes break a desktop).

## Change an entry

Edit the row in `docs/deviations.md` and the entry in `tailoring.xml` in the same commit,
then `python3 -I -B -m unittest discover -s tests -p test_tailoring.py`. A new
scap-security-guide version: `python3 -I tools/check-tailoring.py` (every unselected rule
and every variable still in the profile), then scan again; the review date covers the rest.
