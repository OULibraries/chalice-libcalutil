import requests
import json
import logging
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
    # We could save this somewhere for reuse, but this function will get called once an hour in production
    # and we're not doing anything else with libcal at this time.
    libcal_oauth_token = get_oauth_token(creds)

    # Get events from various calendars and combine them in to a single list, sorted by start time.
    # This is a missing-but-hoped-for feature in the libcal API.
    headers = {}
    headers["Authorization"] = "Bearer %s" % (libcal_oauth_token)
    calendars = [
        "https://libcal.ou.edu/1.1/events?cal_id=12024&category=57017,57014&limit=3",
        "https://libcal.ou.edu/1.1/events?cal_id=11976&category=57022,57021&limit=3",
        "https://libcal.ou.edu/1.1/events?cal_id=12022&category=57025,57026&limit=3",
        "https://libcal.ou.edu/1.1/events?cal_id=2267&category=57018,57020&limit=3",
        "https://libcal.ou.edu/1.1/events?cal_id=12025&category=57028,57027&limit=3",
        "https://libcal.ou.edu/1.1/events?cal_id=12221&category=57031,57032&limit=3",
        "https://libcal.ou.edu/1.1/events?cal_id=12023&category=59730,59731&limit=3",
    ]
    all_events = []
    for cal in calendars:
        events_resp = requests.get(cal, headers=headers)
        events_json = events_resp.json()
        all_events.extend(events_json["events"])

    # Sort by start time could be weird for long running events...
    # Going with simplest solution until we can prove that we don't need something better.
    sorted(all_events, key=lambda event: event["start"])

    # TODO think about whether to move this to a different bucket...specifically one without versioning turned on.
    # TODO do we want to add an Expires header here
    s3 = boto3.resource("s3")
    s3object = s3.Object("ul-web-services", "libcal/events/all.json")
    s3object.put(
        Body=(bytes(json.dumps(events_json).encode("UTF-8"))),
        ContentEncoding="UTF-8",
        ContentType="application/json",
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
