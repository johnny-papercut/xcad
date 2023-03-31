import datetime
import os

import googleapiclient.discovery
import pytz
import requests
from flask import Flask
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.errors import ResumableUploadError
from googleapiclient.http import MediaFileUpload, HttpError
from google.oauth2.credentials import Credentials
from google.cloud import bigquery
from google.oauth2 import service_account

SETTINGS = {
    'debug': True,
    'xbox_api_base': 'https://xbl.io/api/v2',
    'profile_table': 'zirekyle-main.xcad.profiles',
    'profiles': {},
}

api = Flask(__name__)


def load_profiles():
    """ Load profile data from BigQuery """

    bq = initialize_bigquery_client()
    print(bq.query(f"SELECT * FROM `{SETTINGS.get('profile_table')}`").result())
    profiles = [profile for profile in bq.query(f"SELECT * FROM `{SETTINGS.get('profile_table')}`").result()]

    for profile in profiles:
        SETTINGS['profiles'][profile.xbox_gamertag] = {
            'xbox_api_key': profile.xbox_api_key,
            'youtube_playlist': profile.youtube_playlist,
            'youtube_client_id': profile.youtube_client_id,
            'youtube_client_secret': profile.youtube_client_secret,
            'youtube_token': profile.youtube_token,
            'youtube_refresh_token': profile.youtube_refresh_token,
        }


def is_local() -> bool:
    """ Check if this is running locally or not """
    return os.path.exists('bigquery.json')


def initialize_bigquery_client():
    """ Initialize BQ client with local or implied credentials """

    if not os.path.exists('bigquery.json'):
        return bigquery.Client()

    credentials = service_account.Credentials.from_service_account_file(
        'bigquery.json', scopes=["https://www.googleapis.com/auth/cloud-platform"])

    return bigquery.Client(credentials=credentials)


def update_tokens(profile: str, token: str, refresh: str):
    """ Set the YouTube tokens in BigQuery """

    bq = initialize_bigquery_client()
    bq.query(f"UPDATE `{SETTINGS.get('profiles_table')}` "
             f"SET youtube_token = '{token}', youtube_refresh_token = '{refresh}' "
             f"WHERE xbox_gamertag = '{profile}'")
    bq.close()


def manual_auth_youtube(profile: str, env: bool = False, client_id: str = '', client_secret: str = ''):
    """ Manually authenticate to YouTube """

    load_profiles()

    if env:
        client_id = os.environ.get('youtube_client_id')
        client_secret = os.environ.get('youtube_client_secret')
    else:
        if client_id == '':
            client_id = SETTINGS.get('profiles').get(profile).get('youtube_client_id')
        if client_secret == '':
            client_secret = SETTINGS.get('profiles').get(profile).get('youtube_client_secret')

    credentials = InstalledAppFlow.from_client_config(
        client_config={
            "installed": {
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uris": ["http://localhost", "urn:ietf:wg:oauth:2.0:oob"],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://accounts.google.com/o/oauth2/token"
            }
        },
        scopes=['https://www.googleapis.com/auth/youtube']
    ).run_local_server(port=0)

    update_tokens(profile, credentials.token, credentials.refresh_token)

    return credentials


def auth_youtube(profile: str):     # -> googleapiclient.discovery.Resource
    """ Authenticate to YouTube and return a YouTube API client connection """

    if SETTINGS.get('debug'):
        print(f"[Profile: {profile}] Authenticating to YouTube...")

    settings = SETTINGS.get('profiles').get(profile)

    credentials = Credentials(
        client_id=settings.get('youtube_client_id'),
        client_secret=settings.get('youtube_client_secret'),
        token=settings.get('youtube_token'),
        refresh_token=settings.get('youtube_refresh_token'),
        token_uri='https://accounts.google.com/o/oauth2/token',
        scopes=['https://www.googleapis.com/auth/youtube']
    )

    credentials.refresh(Request())

    if credentials and not credentials.valid:
        if credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
            update_tokens(profile, credentials.token, credentials.refresh_token)
        else:
            return None

    return googleapiclient.discovery.build('youtube', 'v3', credentials=credentials)


def get_last_playlist_items(youtube, profile: str) -> list:
    """ Get the titles of the last 50 YouTube playlist videos """

    if SETTINGS.get('debug'):
        print(f"[Profile: {profile}] Getting playlist titles from YouTube...")

    settings = SETTINGS.get('profiles').get(profile)

    print(settings)
    titles = []
    page_token = None

    while len(titles) < 1 or page_token:

        try:
            response = youtube.playlistItems().list(
                part='contentDetails,snippet',
                playlistId=settings.get('youtube_playlist'),
                maxResults=50,
                pageToken=page_token,
            ).execute()
        except HttpError as e:
            print(f"list error: {e}")
            return []

        if len(response.get('items')) < 1:
            break

        page_token = response.get('nextPageToken')

        for item in response.get('items'):

            if item.get('snippet').get('title') == 'Deleted video':
                continue

            titles.append(item.get('snippet').get('title'))

    return titles


def get_xbox_capture_list(profile: str) -> list:
    """ Get data about recent Xbox captures """

    if SETTINGS.get('debug'):
        print(f"[Profile: {profile}] Getting capture data from Xbox...")

    settings = SETTINGS.get('profiles').get(profile)

    clips = []

    for clip in requests.get(
            f"{SETTINGS.get('xbox_api_base')}/dvr/gameclips",
            headers={'accept': '*/*', 'x-authorization': settings.get('xbox_api_key')},).json().get('values'):

        clip_datetime = datetime.datetime.strptime(clip.get('uploadDate').split('.')[0], '%Y-%m-%dT%H:%M:%S')

        if clip_datetime < datetime.datetime(2023, 3, 18):
            continue

        clip_data = {
            'gamertag': profile,
            'uri': clip.get('contentLocators')[0].get('uri'),
            'game': clip.get('titleName').replace('\u00ae', ''),
            'datetime': clip_datetime.replace(tzinfo=datetime.timezone.utc).astimezone(pytz.timezone('US/Central')),
        }

        clip_data['title'] = f"{clip_data.get('game')} - {clip_data.get('datetime').strftime('%m-%d-%Y %H:%M:%S')}"
        clips.append(clip_data)

    return sorted(clips, key=lambda x: x.get('datetime'))


def download_capture(capture_data: dict, profile: str) -> tuple:
    """ Download a specific capture """

    if SETTINGS.get('debug'):
        print(f"[Profile: {profile}] Downloading capture: {capture_data.get('title')} ...")

    dl = requests.get(capture_data.get('uri'), stream=True)

    try:
        with open(f"{capture_data.get('title').replace(':', '')}.mp4", "wb") as download:
            for chunk in dl.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    download.write(chunk)
    except requests.exceptions.StreamConsumedError as e:
        return False, e

    return True, True


def upload_capture_to_youtube(youtube, capture_data, profile) -> tuple:
    """ Upload a capture to YouTube and add to the given playlist """

    print(f"[Profile: {profile}] Uploading capture: {capture_data.get('title')} ...")

    media = MediaFileUpload(f"{capture_data.get('title').replace(':', '')}.mp4", mimetype='video/mp4', resumable=True)

    request = youtube.videos().insert(
        part="snippet,status",
        body={
          "snippet": {
            "description": "This video was automatically uploaded from XCAD.",
            "title": capture_data.get('title')
          },
          "status": {
            "privacyStatus": "unlisted"
          }
        },
        media_body=media
    )

    try:
        response = request.execute()
    except (ResumableUploadError, HttpError) as e:
        if ' you have exceeded your ' in e.reason:
            return False, "quota"
        else:
            return False, e

    video_id = response.get('id')

    request = youtube.playlistItems().insert(
        part="snippet",
        body={
          "snippet": {
            "playlistId": SETTINGS.get('profiles').get(profile).get('youtube_playlist'),
            "resourceId": {
              "kind": "youtube#video",
              "videoId": video_id
            }
          }
        }
    )

    request.execute()
    return True, True


@api.route("/process/<string:profile>/<int:count>")
def process_count(profile: str, count: int):
    """ Process a specific count of videos """
    return process(profile, count)


@api.route("/process/")
def process(profile: str = '', count: int = -1):
    """ Main function, processes everything """

    results = {'success': [], 'fail': []}

    if profile == 'all' or profile == '':
        profiles = SETTINGS.get('profiles').keys()
    else:
        profiles = [profile]

    print(f"Running XCAD with following parameters - "
          f"{'' if count < 1 else f'Count: {count} | '}Profiles: {', '.join(profiles)}")

    for profile in profiles:
        youtube_api = auth_youtube(profile)
        existing = get_last_playlist_items(youtube_api, profile)

        if SETTINGS.get('debug') and not existing:
            print("Quota exceeded, stopping operation.")
            return

        captures = get_xbox_capture_list(profile)

        for capture in captures:

            if capture.get('title') in existing:
                continue

            success, message = download_capture(capture, profile)

            if not success:
                results['fail'].append((profile, capture.get('title'), f"error while downloading: {message}"))
                if message == 'quota':
                    print("Quota exceeded, stopping operation.")
                    return results, 403 if results.get('fail') else 200

            else:
                success, message = upload_capture_to_youtube(youtube_api, capture, profile)

                if not success:
                    results['fail'].append((profile, capture.get('title'), f"error while uploading: {message}"))

                else:
                    results['success'].append((profile, capture.get('title')))

            os.remove(f"{capture.get('title').replace(':', '')}.mp4")

            if -1 < count <= (len(results.get('fail')) + len(results.get('success'))):
                break

    print(f"Uploads - Success: {len(results.get('success'))} Failed: {len(results.get('fail'))}")

    if SETTINGS.get('debug') and results.get('success'):
        print("The following videos uploaded successfully:")
        for profile, title in results.get('success'):
            print(f"[{profile}] {title}")

    if results.get('fail'):
        print("The following videos failed to upload:")
        for profile, title, error in results.get('fail'):
            print(f"[{profile}] {title} - {error}")

    return results, 403 if results.get('fail') else 200


@api.route("/")
def index():
    """ Index page """

    return "xcad", 200


if __name__ == '__main__':

    load_profiles()
    api.run()
