#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8

"""
Fetch data from the Strava API.
"""

from __future__ import annotations
from datetime import datetime, timezone, timedelta

import meerschaum as mrsm
from meerschaum.connectors import make_connector
from meerschaum.config import get_plugin_config, write_plugin_config
from meerschaum.utils.prompt import prompt
from meerschaum.utils.typing import Any, SuccessTuple
from meerschaum.utils.warnings import warn

required = ['requests']
REFRESH_TOKEN_URL: str = "https://www.strava.com/api/v3/oauth/token"
ATHLETE_URL: str = "https://www.strava.com/api/v3/athlete"
ACTIVITIES_URL: str = "https://www.strava.com/api/v3/athlete/activities"

def setup() -> SuccessTuple:
    """
    Prompt the user for API credentials.
    """
    cf = get_plugin_config(warn=False)
    if cf:
        return True, "Already configured credentials."

    write_plugin_config({
        'auth': {
            'client_id': int(prompt("Client ID:")),
            'client_secret': prompt("Client secret:", is_password=True),
            'refresh_token': prompt("Refresh token:", is_password=True),
        }
    })
    return True, "Success"


def fetch(
        pipe: mrsm.Pipe,
        begin: datetime | None = None,
        end: datetime | None = None,
        **kwargs: Any
    ):
    """
    """
    import requests
    response = requests.get(
        ACTIVITIES_URL,
        params = {
            'after': (int(begin.timestamp()) if begin is not None else None),
            'before': (int(end.timestamp()) if end is not None else None),
            'per_page': 100,
        },
        headers = get_headers(),
    )
    return response.json()


def get_athlete_id() -> int | None:
    """
    Cache and return the athlete ID.
    """
    cf = get_plugin_config()
    if (athete_id := cf.get('athlete', {}).get('id', None)):
        return athlete_id

    import requests
    response = requests.get(ATHLETE_URL, headers=get_headers())
    if not response:
        warn("Failed to get the athlete ID!")
        return None

    cf['athlete'] = response.json()
    write_plugin_config(cf)
    return cf['athlete']['id']


def get_headers() -> dict[str, str]:
    """
    Return the authorization headers.
    """
    return {'Authorization': f"Bearer {get_access_token()}"}


def get_access_token() -> str | None:
    """
    Return the access token to use for requests.
    """
    cf = get_plugin_config()
    expires_at = cf.get('auth', {}).get('expires_at', None)
    if expires_at is None:
        return refresh_access_token()

    expires_at_dt = datetime.fromtimestamp(expires_at).replace(tzinfo=timezone.utc)
    now_dt = datetime.now(timezone.utc)
    if (expires_at_dt - now_dt) <= timedelta(minutes=30):
        return refresh_access_token()

    access_token = cf.get('auth', {}).get('access_token', None)
    if access_token is None:
        return refresh_access_token()

    return access_token


def refresh_access_token() -> str | None:
    """
    Return a new access token.
    """
    import requests
    cf = get_plugin_config()
    response = requests.post(
        REFRESH_TOKEN_URL,
        params = {
            'client_id': cf['auth']['client_id'],
            'client_secret': cf['auth']['client_secret'],
            'grant_type': 'refresh_token',
            'refresh_token': cf['auth']['refresh_token'],
            'f': 'json',
            'scope': 'activity:read_all',
        },
        timeout = 12,
    )
    if not response:
        warn("Failed to refresh access token.")
        return None

    token_payload = response.json()
    cf['auth'] = token_payload
    if not write_plugin_config(cf):
        warn("Failed to save updated tokens!")
    return token_payload['access_token']
