#
# tests for compliance/tailoring.xml (stdlib, no scanner): every entry has a row in
# docs/deviations.md (reason, review date at the top of that file), every row's Tailoring
# column matches the file, both ways (review 2026-11-17, C-1).
#
#   python3 -I -B -m unittest discover -s tests -v
#
# Rows: tables with a Tailoring column; rule ids in backticks in the first cell.
# `unselect`: every id is unselected; `prefix_*` (N): N unselected ids with that prefix.
# `value `var=x``: set-value var = x. `-`: none of the ids in the file.
# That the ids exist in the profile is checked on the host (admin script, oscap).
#
import os
import re
import unittest
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAILORING = os.path.join(HERE, 'compliance', 'tailoring.xml')
DEVIATIONS = os.path.join(HERE, 'docs', 'deviations.md')

X = '{http://checklists.nist.gov/xccdf/1.2}'
P = 'xccdf_org.ssgproject.content_'
PROFILE = P + 'profile_cis_workstation_l2'
RULE = P + 'rule_'
VALUE = P + 'value_'


def read_tailoring(path=TAILORING):
    """-> (profile element, unselected rule ids, {var: value}); short ids (no prefix)"""
    root = ET.parse(path).getroot()
    profiles = root.findall(X + 'Profile')
    if root.tag != X + 'Tailoring' or len(profiles) != 1:
        raise ValueError('want one Tailoring with one Profile')
    prof = profiles[0]
    unselected, values = [], {}
    for el in prof:
        if el.tag == X + 'select':
            if el.get('selected') != 'false' or not el.get('idref', '').startswith(RULE):
                raise ValueError('only rule unselects expected: %s' % el.attrib)
            unselected.append(el.get('idref')[len(RULE):])
        elif el.tag == X + 'set-value':
            var = el.get('idref', '')
            if not var.startswith(VALUE) or var[len(VALUE):] in values:
                raise ValueError('bad or repeated set-value: %s' % var)
            values[var[len(VALUE):]] = (el.text or '').strip()
        elif el.tag != X + 'title':
            raise ValueError('unexpected element %s' % el.tag)
    return prof, unselected, values


def read_rows(path=DEVIATIONS):
    """-> [(line number, [rule ids], tailoring cell, rule cell)] of tables with a Tailoring column"""
    rows, in_table = [], False
    with open(path, encoding='ascii') as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip('\n')
            if not line.startswith('|'):
                in_table = False
                continue
            cells = [c.strip() for c in line.strip('|').split('|')]
            if cells[0] == 'Rule':
                in_table = cells[-1] == 'Tailoring'
                continue
            if not in_table or set(cells[0]) <= set('-'):
                continue
            ids = re.findall(r'`([a-z0-9_-]+\*?)`', cells[0])
            rows.append((n, ids, cells[-1], cells[0]))
    return rows


def check(unselected, values, rows):
    """-> list of problems (empty = consistent)"""
    bad = []
    want_unselect, want_values, known = set(), {}, set()
    for n, ids, cell, rule in rows:
        where = 'deviations.md line %d' % n
        if cell == 'unselect':
            if not ids:
                bad.append('%s: unselect without a rule id' % where)
            for i in ids:
                if i.endswith('*'):
                    m = re.search(r'`%s` \((\d+)\)' % re.escape(i), rule)
                    got = sorted(u for u in unselected if u.startswith(i[:-1]))
                    if not m:
                        bad.append('%s: %s without a (count)' % (where, i))
                    elif len(got) != int(m.group(1)):
                        bad.append('%s: %s: %d in the file, row says %s'
                                   % (where, i, len(got), m.group(1)))
                    want_unselect.update(got)
                else:
                    want_unselect.add(i)
        elif cell.startswith('value '):
            pairs = re.findall(r'`([a-z0-9_]+)=([^`]+)`', cell)
            if not pairs:
                bad.append('%s: value without `var=value`' % where)
            for var, val in pairs:
                if var in want_values:
                    bad.append('%s: %s in two rows' % (where, var))
                want_values[var] = val
        elif cell == '-':
            known.update(i for i in ids if not i.endswith('*'))
        else:
            bad.append('%s: Tailoring cell %r (unselect, value ..., -)' % (where, cell))
    for i in sorted(want_unselect - set(unselected)):
        bad.append('row says unselect, not in tailoring.xml: %s' % i)
    for i in sorted(set(unselected) - want_unselect):
        bad.append('unselected in tailoring.xml, no unselect row: %s' % i)
    for i in sorted(known & set(unselected)):
        bad.append('row says "-", but unselected: %s' % i)
    if len(unselected) != len(set(unselected)):
        bad.append('repeated unselect in tailoring.xml')
    for var in sorted(set(want_values) | set(values)):
        if want_values.get(var) != values.get(var):
            bad.append('value %s: deviations.md %r, tailoring.xml %r'
                       % (var, want_values.get(var), values.get(var)))
    return bad


class TailoringFile(unittest.TestCase):

    def test_profile(self):
        prof, unselected, values = read_tailoring()
        self.assertEqual(prof.get('extends'), PROFILE)
        self.assertTrue(prof.get('id').startswith(PROFILE + '_'))
        self.assertTrue(unselected)
        self.assertTrue(values)

    def test_matches_deviations(self):
        _, unselected, values = read_tailoring()
        self.assertEqual(check(unselected, values, read_rows()), [])

    def test_review_date(self):
        with open(DEVIATIONS, encoding='ascii') as f:
            text = f.read()
        self.assertRegex(text, r'\nReview: every row by \d{4}-\d{2}-\d{2}')

    def test_ascii(self):
        with open(TAILORING, 'rb') as f:
            f.read().decode('ascii')

    def test_check_finds_problems(self):
        rows = [(1, ['a_rule'], 'unselect', ''), (2, ['b_rule'], '-', ''),
                (3, ['c_rule'], 'value `var_c=2`', ''), (4, ['p_*'], 'unselect', '`p_*` (2)')]
        ok = ['a_rule', 'p_x', 'p_y']
        v = {'var_c': '2'}
        self.assertEqual(check(ok, v, rows), [])
        self.assertIn('row says unselect, not in tailoring.xml: a_rule', check(ok[1:], v, rows))
        self.assertIn('unselected in tailoring.xml, no unselect row: z_rule',
                      check(ok + ['z_rule'], v, rows))
        self.assertIn('row says "-", but unselected: b_rule',
                      check(ok + ['b_rule'], v, rows + [(5, ['b_rule'], 'unselect', '')]))
        self.assertIn('deviations.md line 4: p_*: 3 in the file, row says 2',
                      check(ok + ['p_z'], v, rows))
        self.assertIn("value var_c: deviations.md '2', tailoring.xml '1'",
                      check(ok, {'var_c': '1'}, rows))
        self.assertIn("value var_d: deviations.md None, tailoring.xml '1'",
                      check(ok, dict(v, var_d='1'), rows))
        self.assertTrue(check(ok, v, rows + [(6, ['d'], 'skip', '')]))


if __name__ == '__main__':
    unittest.main()
