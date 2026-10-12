"""Map one protected Kernel field per OTP box; never retrieve or split a secret.

Kernel's credential fill API writes complete field values. A split SMS widget
therefore uses a matching Kernel-hosted collection with one sensitive field per
digit. Layout helpers use public metadata; redaction helpers inspect only
already-rendered values in backend memory, never read values from the vault.
"""
from .login import normalize_controls, sms_otp_controls
from .store import AccessError


def split_fields(count):
    return ['code_digit_' + str(index + 1) for index in range(count)]


def split_bindings(bindings):
    return (4 <= len(bindings) <= 8 and
            [binding['field'] for binding in bindings] == split_fields(len(bindings)))


def bindings(plan, record, *, selector, best):
    matched = sms_otp_controls(normalize_controls(list(plan.controls)))
    boxes = sorted((item.control for item in matched if item.control.max_length == 1),
                   key=lambda control: control.index)
    if boxes:
        if (not 4 <= len(boxes) <= 8 or len(boxes) != len(matched) or
                len({box.form_index for box in boxes}) != 1 or
                any(right.index != left.index + 1 for left, right in zip(boxes, boxes[1:]))):
            raise AccessError('The verification boxes are ambiguous. Leave only the intended code form open.', 409)
        if 'totp' in record['fields']:
            raise AccessError('Kernel-generated TOTP cannot yet fill separate digit boxes. Use the website\'s single-code input or another supported verification method.', 409)
        return [{'field': field, 'selector': selector(plan, box)}
                for field, box in zip(split_fields(len(boxes)), boxes)]
    control = best(matched, 'verification code')
    return [{'field': 'totp' if 'totp' in record['fields'] else 'code',
             'selector': selector(plan, control)}]


def collection_fields(bindings):
    split = split_bindings(bindings)
    return [{'name': binding['field'], 'type': 'password', 'required': True,
             'sensitive': True, 'label': (
                 f'Digit {index + 1} of {len(bindings)} (one digit, left to right)'
                 if split else 'Verification code')}
            for index, binding in enumerate(bindings)]


def verify_schema(item, fields):
    expected = [{key: field[key] for key in ('name', 'type', 'required', 'sensitive')}
                for field in fields]
    definitions = (item or {}).get('spec', {}).get('fields', [])
    actual = [{key: field.get(key) for key in ('name', 'type', 'required', 'sensitive')}
              for field in definitions]
    if actual != expected:
        raise AccessError('The verification layout changed after the private form was opened. Inspect the current attempt before requesting a new code form.', 409)


def confirmed_digits(values, count):
    return (len(values) == count and all(isinstance(value, str) and len(value) == 1
            and value in '0123456789' for value in values))


def redactions(values):
    """Keep the complete code, never permanently register single characters.

    Individual rendered digits are masked separately for the current browser
    observation, then forgotten when the widget clears or navigates away.
    """
    if confirmed_digits(values, len(values)):
        return [''.join(values)] if len(values) >= 4 else []
    return [value for value in values if isinstance(value, str) and len(value) > 1]
