import datetime
import os
import sys

import googleapiclient.discovery
import pytz
import requests
from flask import Flask
from google.cloud import bigquery
from google.oauth2 import service_account
from googleapiclient.errors import ResumableUploadError
from googleapiclient.http import MediaFileUpload, HttpError

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
    profiles = [profile for profile in bq.query(f"SELECT * FROM `{SETTINGS.get('profile_table')}`").result()]

    for profile in profiles:
        SETTINGS['profiles'][profile.xbox_gamertag] = {
            'xbox_api_key': profile.xbox_api_key,
            'youtube_channel_id': profile.youtube_channel_id,
            'youtube_playlist': profile.youtube_playlist_id,
        }


def is_local() -> bool:
    """ Check if this is running locally or not """
    return os.path.exists('bigquery.json')


def initialize_bigquery_client():
    """ Initialize BQ client with local or implied credentials """

    if not os.path.exists('credentials.json'):
        return bigquery.Client()

    credentials = service_account.Credentials.from_service_account_file(
        'credentials.json', scopes=["https://www.googleapis.com/auth/cloud-platform"])

    return bigquery.Client(credentials=credentials)


def initialize_youtube_client():
    """ Initialize BQ client with local or implied credentials """

    if not os.path.exists('credentials.json'):
        return googleapiclient.discovery.build('youtube', 'v3')

    credentials = service_account.Credentials.from_service_account_file(
        'credentials.json', scopes=["https://www.googleapis.com/auth/youtube"])

    return googleapiclient.discovery.build('youtube', 'v3', credentials=credentials)


def get_last_playlist_items(youtube, profile: str) -> list:
    """ Get the titles of the last 50 YouTube playlist videos """

    if SETTINGS.get('debug'):
        print(f"[Profile: {profile}] Getting playlist titles from YouTube...")

    settings = SETTINGS.get('profiles').get(profile)

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
            "title": capture_data.get('title'),
            "channelId": profile.get('youtube_channel_id'),
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
    
    load_profiles()

    results = {'success': [], 'fail': []}

    if profile == 'all' or profile == '':
        profiles = SETTINGS.get('profiles').keys()
    else:
        profiles = [profile]

    print(f"Running XCAD with following parameters - "
          f"{'' if count < 1 else f'Count: {count} | '}Profiles: {', '.join(profiles)}")

    for profile in profiles:

        youtube_api = initialize_youtube_client()

        if not youtube_api:
            return "YouTube authentication failure", 401

        existing = get_last_playlist_items(youtube_api, profile)

        if SETTINGS.get('debug') and not existing:
            print("Quota exceeded, stopping operation.")
            return "Quota exceeded, stopping operation.", 200

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

    if len(sys.argv) > 1 and sys.argv[1] == 'process':
        process()

    else:
        api.run()
