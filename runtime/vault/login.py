"""Pure login/code classification and retired local credential-entry guards."""
import json
import re
from dataclasses import replace

from agent.vault_login_classifier import (
    ClassifiedLoginControl, build_inspection_js, classify_login_control,
    classify_otp_controls, _RE_OTP,
)
from .store import AccessError


# Use the native inspection's visibility and label resolution in every backend.
_CONTROLS = 'JSON.parse(' + build_inspection_js('clanker-login-probe') + ')'
_TEXT = "(c.name+' '+c.label).replace(/([a-z0-9])([A-Z])/g,'$1 $2').replace(/[^a-z0-9]/gi,' ')"
_OTP = "(c.autocomplete.split(/\\s+/).includes('one-time-code') || new RegExp(" + json.dumps(_RE_OTP.pattern) + ", 'i').test(" + _TEXT + '))'
_PHONE = "(!" + _OTP + " && (c.maxLength === null || c.maxLength >= 7) && !c.autocomplete.includes('tel-country-code') && !c.autocomplete.includes('tel-extension') && (c.type === 'tel' || c.autocomplete.split(/\\s+/).some(t => t === 'tel' || t === 'tel-national') || /\\b(phone|telephone|mobile|phonenumber|mobilenumber)\\b/i.test(" + _TEXT + ')))'
PHONE_FIELDS = '(' + _CONTROLS + ').some(c => ' + _PHONE + ')'
PASSWORD_FIELDS = '(' + _CONTROLS + ").some(c => c.type === 'password' && !c.autocomplete.includes('new-password') && !" + _OTP + ')'
LOGIN_FIELDS = '(' + _CONTROLS + ").some(c => !" + _OTP + " && (c.type === 'password' && !c.autocomplete.includes('new-password') || c.type === 'email' || c.autocomplete.split(/\\s+/).includes('username') || /\\b(login|username|identifier)\\b/i.test(c.name) || " + _PHONE + '))'
OTP_FIELDS = '(() => {const controls=' + _CONTROLS + '; if(controls.some(c => ' + _OTP + '))return true; const boxes=controls.filter(c => c.maxLength===1 && ["text","tel","number"].includes(c.type)); return boxes.length>=4 && boxes.length<=8 && boxes.every((c,i) => c.formIndex===boxes[0].formIndex && (!i || c.index===boxes[i-1].index+1));})()'


def normalize_phone(value):
    if not isinstance(value, str) or len(value) > 64 or not re.fullmatch(r'\+?[0-9\s().-]+', value.strip()):
        raise AccessError('Enter a phone number in the format requested by the website.')
    number = re.sub(r'[\s().-]', '', value.strip())
    if not re.fullmatch(r'\+?[0-9]{7,15}', number):
        raise AccessError('Enter a phone number with 7 to 15 digits, including the country code if required.')
    return number


def phone_fills(controls, number):
    controls = normalize_controls(controls)
    otp_indexes = {c.control.index for c in classify_otp_controls(controls)}
    candidates = []
    for control in controls:
        if (control.index in otp_indexes or control.max_length is not None and control.max_length < 7 or
                any(t in control.autocomplete.split() for t in ('tel-country-code', 'tel-extension'))):
            continue
        classified = classify_login_control(control)
        if classified and classified.token == 'tel':
            candidates.append(classified)
        elif (control.type in ('text', 'number', '') and
              (control.autocomplete == 'tel-national' or re.search(r'\b(phone|telephone|mobile|phonenumber|mobilenumber)\b',
               re.sub(r'[^a-z0-9]+', ' ', re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', control.name+' '+control.label).lower())))):
            candidates.append(ClassifiedLoginControl(control, 100 if control.autocomplete=='tel-national' else 70, 'tel'))
    if not candidates:
        raise AccessError('Open the phone-number login field before filling this account.', 409)
    score = max(c.score for c in candidates)
    best = [c for c in candidates if c.score == score]
    if len(best) != 1:
        raise AccessError('The phone-number field is ambiguous. Leave only the intended login form open.', 409)
    target = best[0]
    if target.control.max_length is not None and len(number) > target.control.max_length:
        raise AccessError('The saved number is too long for this field. Save it in the format requested by the website.', 409)
    return [{'index': target.control.index, 'token': 'tel', 'value': number}]


def normalize_controls(controls):
    return [replace(c, name=re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', c.name),
                    label=re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', c.label)) for c in controls]


def sms_otp_controls(controls):
    matched=classify_otp_controls(controls)
    if matched:return matched
    boxes=[c for c in controls if c.max_length==1 and c.type in ('text','tel','number')]
    if (4<=len(boxes)<=8 and len({c.form_index for c in boxes})==1 and
            all(b.index==a.index+1 for a,b in zip(boxes,boxes[1:]))):
        return [ClassifiedLoginControl(c,70,'one-time-code') for c in boxes]
    return []


def sms_code_fills(controls, code):
    from agent.vault_login_classifier import build_otp_fills
    matched=sms_otp_controls(controls)
    if not matched:
        raise AccessError('Open the SMS verification-code field before entering the code.', 409)
    boxes=[c for c in matched if c.control.max_length==1]
    if boxes and len(boxes)!=len(code):
        raise AccessError('The SMS code length does not match the website\'s verification fields.', 409)
    fills=build_otp_fills(matched,code)
    lengths={c.index:c.max_length for c in controls}
    if any(lengths[f['index']] is not None and len(f['value'])>lengths[f['index']] for f in fills):
        raise AccessError('The SMS code is too long for the website\'s verification field.', 409)
    return fills


# Cached callers of the retired local writer fail closed. Kernel owns all
# credential collection and browser input; these stubs never inspect a browser.
def prepare_sms_code_fill(turn, access):
    raise AccessError('Local credential entry is retired. Use Kernel vault fill.', 410)


def validate_sms_code_fill(plan, code):
    raise AccessError('Local credential entry is retired. Use Kernel vault fill.', 410)


def write_sms_code_fill(turn, access, plan, code):
    raise AccessError('Local credential entry is retired. Use Kernel vault fill.', 410)


def local_fill(turn, access, *, code=None):
    raise AccessError('Local credential entry is retired. Use Kernel vault fill.', 410)
