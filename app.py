"""
Helper utility to create a combined calendar feed for libcal, a currently-missing feature.
"""

import datetime
import logging
import json
import requests
import boto3

from botocore.exceptions import ClientError
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session
from chalice import Chalice

app = Chalice(app_name="chalice-libcalutil")


@app.schedule("rate(1 hour)")
def update_combined_events(event):
    """Write new version of combined events json feed file."""

    # Get LibCal credentials secret from SecretsManager
    creds = get_secret()

    # Get header token from libcal for authing requests
    # We could save this somewhere for reuse, but this function will get called
    # approximately once an hour in production and we're not doing anything else
    # the credential at this time.
    libcal_oauth_token = get_oauth_token(creds)

    all_events = get_combined_events(libcal_oauth_token)

    if len(all_events) > 2:
        write_combined_events({"events": all_events[0:2]})
    else:
        write_combined_events({"events": all_events})


def get_combined_events(libcal_oauth_token):
    """Query libcal for a list of events from multiple calendars"""

    headers = {}
    headers["Authorization"] = "Bearer %s" % (libcal_oauth_token)

    # We want to get events from various calendars and combine them in to a single
    # list, sorted by start time. This is a missing-but-hoped-for feature in the
    # LibCal API. See docs at https://libcal.ou.edu/admin/api/ (requires login)
    #
    # The calendars that we care about are:
    #
    # Cal ID    Name
    # ------    -----
    #  12024     339
    #  11976     General
    #  12022     Learning Lab Classroom
    #   2267     Library Maker Space
    #  12025     LL118
    #  12221     LL121E
    #  12023     LL123

    # For all of the above, we're querying two categories of event
    # - OU Libraries Event
    # - Research Wrokshops
    calendars = [
        "https://libcal.ou.edu/1.1/events?cal_id=12024&category=57017,57014&limit=5&days=60",
        "https://libcal.ou.edu/1.1/events?cal_id=11976&category=57022,57021&limit=5&days=60",
        "https://libcal.ou.edu/1.1/events?cal_id=12022&category=57025,57026&limit=5&days=60",
        "https://libcal.ou.edu/1.1/events?cal_id=2267&category=57018,57020&limit=5&days=60",
        "https://libcal.ou.edu/1.1/events?cal_id=12025&category=57028,57027&limit=5&days=60",
        "https://libcal.ou.edu/1.1/events?cal_id=12221&category=57031,57032&limit=5&days=60",
        "https://libcal.ou.edu/1.1/events?cal_id=12023&category=59730,59731&limit=5&days=60",
    ]

    all_events = []
    for cal in calendars:
        events_resp = requests.get(cal, headers=headers, timeout=5)
        events_json = events_resp.json()
        all_events.extend(events_json["events"])

    # Sort by start time could be weird for long running events...
    # Going with simplest solution until we can prove that we don't need something better.
    sorted(all_events, key=lambda event: event["start"])


def write_combined_events(events_json):
    """Write events json to S3 bucket"""

    # Default expiration is 24 hours, which is too long. Let's try 20 minutes
    expiration = datetime.datetime.now() + datetime.timedelta(minutes=20)

    # TODO think about whether to move this to a different bucket...specifically one without
    # versioning turned on.
    # TODO are we using the right timout for the Expires header here?
    s3 = boto3.resource("s3")
    s3object = s3.Object("ul-web-services", "libcal/events/all.json")
    s3object.put(
        Body=(bytes(json.dumps(events_json).encode("UTF-8"))),
        ContentEncoding="UTF-8",
        ContentType="application/json",
        Expires=expiration,
    )


def get_secret():
    """Get JSON blob of secrets required to atuh with libcal API from AWS Secrets Manager."""
    secret_name = "prod/lambdaCal/LibcalEventsRO"
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(service_name="secretsmanager", region_name=region_name)

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    # Decrypts secret using the associated KMS key.
    secret = get_secret_value_response["SecretString"]

    return json.loads(secret)


# Get Oauth token
def get_oauth_token(creds):
    """Get oauth token from libcal using Client Credentials Flow"""
    client_id = creds["client_id"]
    client_secret = creds["secret"]
    client = BackendApplicationClient(client_id=client_id)
    oauth = OAuth2Session(client=client)
    token = oauth.fetch_token(
        token_url="https://libcal.ou.edu/1.1/oauth/token",
        client_id=client_id,
        client_secret=client_secret,
    )
    return token["access_token"]
