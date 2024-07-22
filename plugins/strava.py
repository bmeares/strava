#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8

"""
Fetch data from the Strava API.
"""

from __future__ import annotations
from datetime import datetime, timezone, timedelta
import pathlib
import time
import json
import urllib.parse

import meerschaum as mrsm
from meerschaum.config import get_plugin_config, write_plugin_config
from meerschaum.utils.prompt import prompt
from meerschaum.utils.typing import Any, SuccessTuple
from meerschaum.utils.warnings import warn, info
from meerschaum.plugins import api_plugin
from meerschaum.utils.daemon import daemon_action, Daemon
from meerschaum.connectors.poll import retry_connect
from meerschaum.config._paths import ROOT_DIR_PATH
from meerschaum.utils.debug import dprint

__version__ = '0.1.0'
required = ['requests', 'stravalib==2.0.0rc0']

REFRESH_TOKEN_URL: str = "https://www.strava.com/api/v3/oauth/token"
ATHLETE_URL: str = "https://www.strava.com/api/v3/athlete"
ACTIVITIES_URL: str = "https://www.strava.com/api/v3/athlete/activities"
API_JOB_NAME: str = "_strava_api"
API_JOB_PORT: int = 3059
API_JOB_URI: str = f"http://127.0.0.1:{API_JOB_PORT}"
REDIRECT_URL_PATH: str = "/strava/authorization"
AUTHORIZED_PATH: pathlib.Path = ROOT_DIR_PATH / '.strava-auth'

def setup() -> SuccessTuple:
    """
    Prompt the user for API credentials.
    """
    cf = get_plugin_config(warn=False) or {}
    auth_cf = cf.get('auth', {})
    info(
        f"Make sure port {API_JOB_PORT} is open and accessible."
        "\n   If you are running Dockerized Meerschaum, run `mrsm edit config stack` "
        f"and add `{API_JOB_PORT}:{API_JOB_PORT}` under the `api` service."
    )
    try:
        host = auth_cf.get('host_uri') or prompt("Host:", default='localhost')
        client_id = auth_cf.get('client_id') or prompt("Client ID:")
        client_secret = auth_cf.get('client_secret') or prompt("Client secret:", is_password=True)
        refresh_token = auth_cf.get('refresh_token') or prompt("Refresh token:", is_password=True)
    except Exception as e:
        return True, "Success"
    redirect_url = f"http://{host}:{API_JOB_PORT}{REDIRECT_URL_PATH}"

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
        no_dash = True,
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

    auth_url = (
        f"https://www.strava.com/oauth/authorize?client_id={client_id}"
        + f"&redirect_uri={urllib.parse.quote_plus(redirect_url)}"
        + "&approval_prompt=auto&scope=activity%3Aread_all&response_type=code"
    )
    info(f"Click the following link to authorize with Strava:\n\n{auth_url}\n")

    while not AUTHORIZED_PATH.exists():
        time.sleep(0.1)

    mrsm.pprint((True, "Successfully authorized with Strava."))
    AUTHORIZED_PATH.unlink()
    daemon = Daemon(daemon_id=API_JOB_NAME)
    daemon.kill()
    daemon.cleanup()
    return True, "Success"


def fetch(
        pipe: mrsm.Pipe,
        begin: datetime | None = None,
        end: datetime | None = None,
        debug: bool = False,
        **kwargs: Any
    ):
    """
    Fetch activities from Strava.
    """
    import requests
    from stravalib import Client
    client = get_client()

    if not begin:
        begin = pipe.get_sync_time(debug=debug)

    if begin:
        begin -= pipe.get_backtrack_interval(debug=debug)

    activities = client.get_activities(
        after = begin if begin is not None else None,
        before = end if end is not None else None,
    )
    if debug:
        dprint("Iterating over Strava activities...")
    docs = []
    for activity in activities:
        doc = json.loads(activity.json())
        start_date = activity.start_date
        if debug:
            dprint(f"Loading activity from '{start_date}'...")
        try:
            streams = client.get_activity_streams(activity.id)
        except Exception as e:
            streams = {}
            warn(e)
        for key, stream in streams.items():
            doc[f'stream_{key}'] = stream.data

        if 'time' in streams:
            doc['stream_timestamps'] = [
                (start_date + timedelta(seconds=val)).isoformat()
                for val in streams['time'].data
            ]

        if 'latlng' in streams:
            doc['stream_latitude'] = [
                val[0]
                for val in streams['latlng'].data
            ]
            doc['stream_longitude'] = [
                val[1]
                for val in streams['latlng'].data
            ]

        docs.append(doc)

    return docs


def get_client():
    """
    Return the Strava client with the current access token.
    """
    with mrsm.Venv('strava'):
        from stravalib import Client
        client = Client(access_token=get_access_token())
    return client

@api_plugin
def init_api(app):
    from fastapi.responses import HTMLResponse

    @app.get(REDIRECT_URL_PATH, response_class=HTMLResponse)
    def get_strava_authorization(code: str, scope: str):
        refresh_access_token(authorization_code=code)
        with open(AUTHORIZED_PATH, 'w', encoding='utf-8') as f:
            json.dump({'authorization_code': code, 'scope': scope}, f)

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
