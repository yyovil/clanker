"""Conservative, model-blind identity autofill for the owner's private forms."""
import json
import re
from datetime import date

from agent.vault_login_classifier import build_fill_js
from .store import AccessError


_NAME_TOKENS = ('given-name', 'additional-name', 'family-name', 'name')
_BIRTH_TOKENS = ('bday-day', 'bday-month', 'bday-year', 'bday')
_DATE_FORMAT = re.compile(r'\b(?:yyyy([-/. ])mm\1dd|dd([-/. ])mm\2yyyy|mm([-/. ])dd\3yyyy)\b', re.I)


def _text(control):
    return re.sub(r'[^a-z0-9]+', ' ', control.name.lower() + ' ' + control.label.lower()).strip()


def _classify(control, kind):
    if control.type not in ('text', 'date', 'number', 'select', ''):
        return None
    tokens = control.autocomplete.lower().split()
    if any(token in tokens for token in ('one-time-code', 'username', 'cc-name')):
        return None
    text = _text(control)
    if kind == 'name':
        if re.search(r'\b(?:company|business|cardholder|emergency|username)\b', text):return None
        for token in _NAME_TOKENS:
            if token in tokens:return token, 100
        for pattern, token in (
            (r'\b(?:first|given)\b.*\bmiddle\b.*\bnames?\b', 'given-name'),
            (r'\b(?:(?:first|given) name|firstname|givenname)\b', 'given-name'),
            (r'\b(?:middle name|middlename|additional name)\b', 'additional-name'),
            (r'\b(?:(?:last|family) name|lastname|familyname|surname)\b', 'family-name'),
            (r'\b(?:(?:full|legal|passenger|traveller|traveler|recipient|your) name|fullname)\b', 'name'),
        ):
            if re.search(pattern, text):return token, 70
        if control.name.strip().lower() == 'name' and text in ('name', 'name name'):
            return 'name', 70
    if kind == 'dob':
        for token in _BIRTH_TOKENS:
            if token in tokens:return token, 100
        if re.search(r'\b(?:dob|date of birth|birth date|birthdate|birthday|birth day)\b', text):
            for part in ('day', 'month', 'year'):
                if re.search(r'\b' + part + r'\b', text) and not _DATE_FORMAT.search(control.label):
                    return 'bday-' + part, 70
            return 'bday', 70
    if kind == 'gender':
        # Gender is an explicit owner choice; it cannot establish document sex.
        if re.search(r'\bsex\b', text):return None
        if 'gender' in tokens or re.search(r'\bgender\b', text):return 'gender', 100 if 'gender' in tokens else 70
    return None


def _targets(controls, kind):
    candidates = {}
    for control in controls:
        classified = _classify(control, kind)
        if classified:
            token, score = classified
            candidates.setdefault(token, []).append((score, control))
    targets = {}
    for token, matches in candidates.items():
        if len(matches) != 1:
            raise AccessError('The personal identity fields are ambiguous. Leave only the intended person\'s form open.', 409)
        targets[token] = matches[0][1]
    if not targets:
        raise AccessError('Open the intended ' + kind + ' field before filling your saved details.', 409)
    if len({control.form_index for control in targets.values()}) > 1:
        raise AccessError('The personal identity fields span multiple forms. Open only the intended person\'s form.', 409)
    return targets


def _date_value(control, birthday):
    if control.type == 'date':return birthday.isoformat()
    formats = {match.group(0).lower() for match in _DATE_FORMAT.finditer(control.label)}
    if len(formats) != 1:
        raise AccessError('Inspect the website\'s date-of-birth format before retrying the saved date. Do not ask for the saved date again.', 409)
    template = formats.pop()
    return template.replace('yyyy', str(birthday.year).zfill(4)).replace('mm', str(birthday.month).zfill(2)).replace('dd', str(birthday.day).zfill(2))


def identity_fills(controls, values, fields):
    fills = []
    for kind in ('name', 'dob', 'gender'):
        if kind not in fields:continue
        targets = _targets(controls, kind)
        saved = values[kind]
        if kind == 'name':
            if 'name' in targets and len(targets) > 1:
                raise AccessError('Both full-name and separate name fields are open. Inspect the intended person\'s form before retrying.', 409)
            available = {token: saved.get(key, '') for token, key in
                         (('given-name', 'given_name'), ('additional-name', 'middle_name'), ('family-name', 'family_name'))}
            if 'additional-name' not in targets and saved.get('middle_name'):
                available['given-name'] = saved['given_name'] + ' ' + saved['middle_name']
            available['name'] = ' '.join(saved[key] for key in ('given_name', 'middle_name', 'family_name') if saved.get(key))
        elif kind == 'dob':
            birthday = date.fromisoformat(saved['date_of_birth'])
            if 'bday' in targets:
                if len(targets) > 1:raise AccessError('Multiple date-of-birth formats are open. Inspect the intended form before retrying.', 409)
                available = {'bday': _date_value(targets['bday'], birthday)}
            else:
                if set(targets) != {'bday-day', 'bday-month', 'bday-year'}:
                    raise AccessError('Open all day, month and year fields before filling the saved date of birth.', 409)
                available = {'bday-day': str(birthday.day), 'bday-month': str(birthday.month), 'bday-year': str(birthday.year).zfill(4)}
        else:
            available = {'gender': saved['gender']}
        additions = [{'index': control.index, 'token': token, 'value': available[token]}
                     for token, control in targets.items() if available.get(token)]
        if not additions:
            raise AccessError('The visible name fields need a name component that is not saved. Update only that required component in Personal info.', 409)
        fills.extend(additions)
    return fills


def build_personal_fill_js(fills, *, expected_origin, nonce, phone_context_js=None):
    """Reuse the exact-origin native writer, adding explicit select aliases."""
    script = build_fill_js(fills, expected_origin=expected_origin, nonce=nonce).replace(
        'HTMLInputElement.prototype', "(el.tagName==='TEXTAREA'?HTMLTextAreaElement:HTMLInputElement).prototype")
    # Match visible labels as well as option values; never choose the first
    # option or infer gender from a title. Month names support common DOB menus.
    script = script.replace('const want = norm(f.value);', '''const aliases = {
          male: ['male', 'man', 'm'], female: ['female', 'woman', 'f'],
          nonbinary: ['nonbinary', 'non-binary', 'non binary'], other: ['other'],
          prefer_not_to_say: ['prefer not to say', 'prefer_not_to_say', 'rather not say']
        };
        const months = ['january','february','march','april','may','june','july','august','september','october','november','december'];
        const want = norm(f.value);
        const accepted = new Set([want, want.replace(/^0/, '')]);
        if (f.token === 'bday-day' || f.token === 'bday-month') accepted.add(want.padStart(2, '0'));
        if (f.token === 'gender') for (const value of aliases[want] || []) accepted.add(value);
        if (f.token === 'bday-month' && Number(want) >= 1 && Number(want) <= 12) {
          const month = months[Number(want)-1]; accepted.add(month); accepted.add(month.slice(0,3));
          accepted.add(want.padStart(2, '0'));
        }
        const matches = Array.from(el.options).filter(o => !o.disabled && accepted.has(norm(o.textContent)));
        const byValue = Array.from(el.options).filter(o => !o.disabled && accepted.has(norm(o.value)));
        const candidates = matches.length ? matches : byValue;''')
    script = script.replace('const opt = Array.from(el.options).find((o) => [o.value, o.textContent].some((t) => norm(t) === want || norm(t) === want.replace(/^0/, "")));',
                            'const opt = candidates.length === 1 ? candidates[0] : null;')
    script = script.replace('const setter = Object.getOwnPropertyDescriptor',
                            "const inputValue = f.token === 'gender' ? f.value.replace(/_/g, ' ').replace(/^nonbinary$/, 'non-binary') : f.value;\n      const setter = Object.getOwnPropertyDescriptor")
    script = script.replace('setter.set.call(el, f.value)', 'setter.set.call(el, inputValue)').replace('el.value = f.value;', 'el.value = inputValue;')
    # Report only fixed reasons and counts. A React handler can reject, truncate
    # or detach a phone input without throwing, so a nonempty value is not proof.
    script = script.replace('let filled = 0;', 'let filled = 0; let missing = 0; let rejected = 0; let exceptions = 0; let contextChanged = 0;')
    national_codes = {str(fill['index']): fill['phone_country_code'] for fill in fills if fill.get('phone_country_code')}
    if national_codes:
        if not phone_context_js:
            raise ValueError('National phone filling requires a fresh calling-code inspection.')
        script = script.replace('const norm =', '''const phoneCodes = ''' + json.dumps(national_codes) + ''';
  const phoneCodeStillMatches = (f, el) => {
    const expected = phoneCodes[String(f.index)];
    if (!expected) return true;
    const observation = (''' + phone_context_js + ''')[String(f.index)];
    if (!observation || observation.ambiguous) return false;
    return observation.codes.length === 1 ? observation.codes[0] === expected :
      (el.autocomplete || '').split(/\\s+/).includes('tel-national');
  };
  const norm =''')
        script = script.replace('el.focus();', '''el.focus();
      if (!phoneCodeStillMatches(f, el)) { contextChanged += 1; rejected += 1; continue; }''')
    script = script.replace('return JSON.stringify({ refused: "origin_changed", found: window.location.origin });',
                            'return JSON.stringify({ refused: "origin_changed", filled: 0 });')
    script = script.replace('if (!el || (f.token === "current-password" && el.type !== "password")) continue;',
                            'if (!el || (f.token === "current-password" && el.type !== "password")) { missing += 1; continue; }')
    script = script.replace('el.dispatchEvent(new Event("change", { bubbles: true })); filled += 1; }',
                            'el.dispatchEvent(new Event("change", { bubbles: true })); filled += 1; } else { rejected += 1; }')
    script = script.replace('if (el.value.length > 0) filled += 1;', '''if (f.token === 'tel') el.blur();
      if (el.isConnected === false) { missing += 1; continue; }
      const samePhone = value => String(value || '').replace(/[\\s().-]/g, '');
      const verified = f.token === 'tel' ? samePhone(el.value) === samePhone(inputValue) : el.value.length > 0;
      if (verified) filled += 1; else rejected += 1;''')
    if national_codes:
        script = script.replace("const samePhone =", "if (!phoneCodeStillMatches(f, el)) { contextChanged += 1; rejected += 1; continue; }\n      const samePhone =")
    script = script.replace('catch (e) { /* skip */ }', 'catch (e) { exceptions += 1; }')
    script = script.replace('return JSON.stringify({ filled });', '''return JSON.stringify({ filled, missing, rejected, exceptions,
    stage: exceptions ? 'write_exception' : missing ? 'control_changed' : contextChanged ? 'phone_context_changed' : rejected ? 'value_rejected' : 'complete' });''')
    return script
