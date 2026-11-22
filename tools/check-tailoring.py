#!/usr/bin/env python3
#
# tools/check-tailoring.py - compliance/tailoring.xml against a scap-security-guide data
# stream (no root, read-only): the base profile exists, every unselected rule is selected
# in it, every set-value names a variable a selected rule uses, numbers are numbers.
# Run after a scap-security-guide update, before scanning with the tailoring.
#
#   python3 -I tools/check-tailoring.py [/usr/share/xml/scap/ssg/content/ssg-fedora-ds.xml]
#
# Exit 0 = all ok, 1 = a problem (printed), 2 = usage / unreadable file.
#
import os
import sys
import xml.etree.ElementTree as ET

X = '{http://checklists.nist.gov/xccdf/1.2}'
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAILORING = os.path.join(HERE, 'compliance', 'tailoring.xml')
DS = '/usr/share/xml/scap/ssg/content/ssg-fedora-ds.xml'


def main(argv):
    ds = argv[1] if len(argv) > 1 else DS
    try:
        t = ET.parse(TAILORING).getroot().find(X + 'Profile')
        bench = ET.parse(ds).getroot()
    except (OSError, ET.ParseError) as e:
        print('check-tailoring: %s' % e)
        return 2
    base = next((p for p in bench.iter(X + 'Profile') if p.get('id') == t.get('extends')), None)
    if base is None:
        print('FAIL base profile not in %s: %s' % (ds, t.get('extends')))
        return 1
    selected = {s.get('idref') for s in base.findall(X + 'select') if s.get('selected') == 'true'}
    rules = {r.get('id'): r for r in bench.iter(X + 'Rule')}
    values = {v.get('id'): v for v in bench.iter(X + 'Value')}
    used = {c.get('value-id') for rid in selected if rid in rules
            for c in rules[rid].iter(X + 'check-export')}
    bad = 0
    n_sel = n_val = 0
    for el in t:
        ref = el.get('idref')
        if el.tag == X + 'select':
            n_sel += 1
            if ref not in rules:
                print('FAIL unselected rule not in the data stream: %s' % ref); bad += 1
            elif ref not in selected:
                print('FAIL unselected rule not selected in the base profile: %s' % ref); bad += 1
        elif el.tag == X + 'set-value':
            n_val += 1
            v = values.get(ref)
            if v is None:
                print('FAIL set-value of an unknown variable: %s' % ref); bad += 1
            elif ref not in used:
                print('FAIL set-value of a variable no selected rule uses: %s' % ref); bad += 1
            elif v.get('type') == 'number' and not (el.text or '').strip().lstrip('-').isdigit():
                print('FAIL %s is a number, set-value %r' % (ref, el.text)); bad += 1
    print('%s: %d unselected, %d set-value, base %s (%d rules): %s'
          % (os.path.basename(TAILORING), n_sel, n_val, t.get('extends').split('_profile_')[-1],
             len(selected & set(rules)), 'ok' if not bad else '%d problem(s)' % bad))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
