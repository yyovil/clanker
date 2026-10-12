"""Authorize trusted autofill only against requester-owned Kernel browsers."""
from urllib.parse import urlsplit

from .store import AccessError


def browser_task_id(turn):
    cloud = turn.service.cloud_browser
    if cloud is None or not getattr(cloud, 'uses_native_tools', False):
        raise AccessError('Start this task\'s authenticated Kernel browser before filling the form.', 409)
    return cloud.native_task_id(turn)


def authorize_supervisor(turn, supervisor):
    if supervisor is None:
        raise AccessError('Start this task\'s Kernel browser before filling the form.', 409)
    if urlsplit(supervisor.cdp_url).hostname in {'127.0.0.1', 'localhost', '::1'}:
        raise AccessError('Local browser execution has been removed. Reopen the form in Kernel.', 403)
    cloud = turn.service.cloud_browser
    if cloud is None or not getattr(cloud, 'uses_native_tools', False):
        raise AccessError('This browser has no verified requester ownership.', 403)
    cloud.assert_supervisor(turn, supervisor)
    return supervisor


def remember_redactions(turn, values):
    cloud = turn.service.cloud_browser
    if cloud is not None and getattr(cloud, 'uses_native_tools', False):
        cloud.remember_redactions(turn, values)
