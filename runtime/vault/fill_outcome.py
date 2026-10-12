"""Value-free fill evidence shared by tools and durable attempt metadata."""
from .store import AccessError

READBACK_STAGES = frozenset({'retained', 'empty', 'target_missing',
    'target_ambiguous', 'binding_changed', 'unavailable', 'invalid_code', 'value_mismatch'})
FIELD_ERRORS = frozenset({'target_changed', 'element_not_found',
    'ambiguous_selector', 'element_not_editable', 'option_not_found',
    'timeout', 'execution_failed'})


def validate_outcome(value):
    """Rebuild a closed schema; never copy arbitrary provider/browser data."""
    def require(condition):
        if not condition:
            raise AccessError('The Kernel fill evidence is invalid.')

    require(isinstance(value, dict) and set(value) == {'provider', 'readback'})
    observed = value['readback']
    require(isinstance(observed, dict) and set(observed) ==
            {'stage', 'expected', 'matched', 'nonempty'})
    require(isinstance(observed['stage'], str) and observed['stage'] in READBACK_STAGES)
    require(type(observed['expected']) is int and 1 <= observed['expected'] <= 32)
    expected = observed['expected']
    require(all(type(observed[name]) is int and 0 <= observed[name] <= expected
                for name in ('matched', 'nonempty')))
    require(observed['nonempty'] <= observed['matched'])
    if observed['stage'] == 'retained':
        require(observed['matched'] == observed['nonempty'] == expected)
    provider = value['provider']
    clean = None
    if provider is not None:
        require(isinstance(provider, dict) and set(provider) == {'status', 'fields'})
        require(provider['status'] in ('completed', 'failed', 'unknown'))
        fields = provider['fields']
        require(isinstance(fields, list) and len(fields) == expected)
        entries, stopped = [], False
        for index, field in enumerate(fields):
            require(isinstance(field, dict) and set(field) in
                    ({'index', 'status'}, {'index', 'status', 'error_code'}))
            require(type(field['index']) is int and field['index'] == index)
            status = field['status']
            require(status in ('filled', 'failed', 'unknown', 'not_attempted'))
            require(status == 'not_attempted' if stopped else status != 'not_attempted')
            entry = {'index': index, 'status': status}
            if 'error_code' in field:
                require(isinstance(field['error_code'], str) and
                        field['error_code'] in FIELD_ERRORS and status in ('failed', 'unknown'))
                entry['error_code'] = field['error_code']
            entries.append(entry)
            stopped = stopped or status in ('failed', 'unknown')
        statuses = {field['status'] for field in entries}
        require((provider['status'] == 'completed' and statuses == {'filled'}) or
                (provider['status'] == 'failed' and 'failed' in statuses and 'unknown' not in statuses) or
                (provider['status'] == 'unknown' and 'unknown' in statuses))
        clean = {'status': provider['status'], 'fields': entries}
    return {'provider': clean, 'readback': {name: observed[name] for name in
            ('stage', 'expected', 'matched', 'nonempty')}}
