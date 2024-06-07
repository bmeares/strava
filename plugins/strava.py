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
from meerschaum.utils.warnings import warn, info
from meerschaum.plugins import api_plugin
from meerschaum.utils.daemon import daemon_action, Daemon
from meerschaum.connectors.poll import retry_connect

required: list[str] = ['requests', 'stravalib']
REFRESH_TOKEN_URL: str = "https://www.strava.com/api/v3/oauth/token"
ATHLETE_URL: str = "https://www.strava.com/api/v3/athlete"
ACTIVITIES_URL: str = "https://www.strava.com/api/v3/athlete/activities"
API_JOB_NAME: str = "_strava_api"
API_JOB_PORT: int = 3059
API_JOB_URI: str = f"http://127.0.0.1:{API_JOB_PORT}"
REDIRECT_URI: str= f"{API_JOB_URI}/strava/authorization"

def setup() -> SuccessTuple:
    """
    Prompt the user for API credentials.
    """
    from stravalib import Client
    cf = get_plugin_config(warn=False)
    auth_cf = cf.get('auth', {})
    client_id = auth_cf.get('client_id') or prompt("Client ID:")
    client_secret = auth_cf.get('client_secret') or prompt("Client secret:", is_password=True)
    refresh_token = auth_cf.get('refresh_token') or prompt("Refresh token:", is_password=True)

    write_plugin_config({
        'auth': {
            'client_id': client_id,
            'client_secret': client_secret,
            'refresh_token': refresh_token,
        }
    })

    conn = mrsm.get_connector('api:strava', uri=API_JOB_URI)
    success, msg = daemon_action(
        action = ['start', 'api'],
        port = API_JOB_PORT,
        name = API_JOB_NAME,
        mrsm_instance = 'sql:memory',
    )
    if not success:
        warn(f"Failed to start Strava API server:\n{msg}")
    if not retry_connect(
        conn,
        enforce_chaining = False,
        enforce_login = False,
        print_on_connect = False,
        warn = False,
    ):
        warn("Failed to start the local Strava API server!")

    client = Client()
    auth_url = client.authorization_url(
        client_id = client_id,
        redirect_uri = REDIRECT_URI,
        scope = 'activity:read_all',
    )
    info(f"Click the following link to authorize with Strava:\n\n{auth_url}\n")
    prompt("Press Enter to continue:", icon=False)

    daemon = Daemon(daemon_id=API_JOB_NAME)
    daemon.kill()
    daemon.cleanup()
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


@api_plugin
def init_api(app):
    from fastapi.responses import HTMLResponse

    @app.get('/strava/authorization', response_class=HTMLResponse)
    def get_strava_authorization(code: str, scope: str):
        refresh_access_token(authorization_code=code)

        return """
        <html>
            <head>
                <title>Authorized with Strava</title>
                <style>
                    * {
                        font-family: "Arial";
                    }
                </style>
            </head>
            <body>
                <h1>Successfully authorized with Strava!</h1>
                <p>You may now close this page.<p>
            </body>
        </html>
        """


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


def refresh_access_token(authorization_code: str | None = None) -> str | None:
    """
    Return a new access token.
    """
    import requests
    cf = get_plugin_config()
    token_key, token_val, grant_type = (
        ('code', authorization_code, 'authorization_code')
        if authorization_code is not None
        else ('refresh_token', cf['auth']['refresh_token'], 'refresh_token')
    )
    params = {
        'client_id': cf['auth']['client_id'],
        'client_secret': cf['auth']['client_secret'],
        'grant_type': grant_type,
        token_key: token_val,
    }
    response = requests.post(
        REFRESH_TOKEN_URL,
        params = params,
        timeout = 12,
    )
    if not response:
        warn("Failed to refresh access token.")
        return None

    token_payload = response.json()
    if 'auth' not in cf:
        cf['auth'] = {}
    cf['auth'].update(token_payload)
    if not write_plugin_config(cf):
        warn("Failed to save updated tokens!")
    return token_payload['access_token']
