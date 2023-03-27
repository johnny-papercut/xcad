import datetime
import os
import pickle

import googleapiclient.discovery
import pytz
import requests
from flask import Flask
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.errors import ResumableUploadError
from googleapiclient.http import MediaFileUpload, HttpError

HEADERS = {'accept': '*/*', 'x-authorization': os.environ.get('XBL_API_KEY')}
API_BASE_URL = 'https://xbl.io/api/v2'
USERNAME = os.environ.get('USERNAME')
PLAYLIST_ID = os.environ.get('PLAYLIST_ID')

DEBUG = True
api = Flask(__name__)


def auth_youtube():     # -> googleapiclient.discovery.Resource
    """ Authenticate to YouTube and return a YouTube API client connection """

    if DEBUG:
        print("Authenticating to YouTube...")

    credentials = None

    if os.path.exists('youtube.pickle'):
        with open('youtube.pickle', 'rb') as token:
            credentials = pickle.load(token)

    if not credentials or not credentials.valid:
        if credentials and credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
        else:
            credentials = InstalledAppFlow.from_client_config(
                client_config={
                    "installed": {
                        "client_id": os.environ.get('YT_CLIENT_ID'),
                        "client_secret": os.environ.get('YT_CLIENT_SECRET'),
                        "redirect_uris": ["http://localhost", "urn:ietf:wg:oauth:2.0:oob"],
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://accounts.google.com/o/oauth2/token"
                    }
                },
                scopes=['https://www.googleapis.com/auth/youtube']
            ).run_local_server(port=0)

        with open('youtube.pickle', 'wb') as token:
            pickle.dump(credentials, token)

    return googleapiclient.discovery.build('youtube', 'v3', credentials=credentials)


def get_last_playlist_items(youtube) -> list:
    """ Get the titles of the last 50 YouTube playlist videos """

    if DEBUG:
        print("Getting playlist titles from YouTube...")

    titles = []
    page_token = None

    while len(titles) < 1 or page_token:

        try:
            response = youtube.playlistItems().list(
                part='contentDetails,snippet',
                playlistId='PLYoQGprQsb0Lud8uz0KyDfQzTr91UXVMU',
                maxResults=50,
                pageToken=page_token,
            ).execute()
        except HttpError:
            return []

        if len(response.get('items')) < 1:
            break

        page_token = response.get('nextPageToken')

        for item in response.get('items'):

            if item.get('snippet').get('title') == 'Deleted video':
                continue

            titles.append(item.get('snippet').get('title'))

    return titles


def get_xbox_capture_list() -> list:
    """ Get data about recent Xbox captures """

    if DEBUG:
        print("Getting capture data from Xbox...")

    clips = []

    for clip in requests.get(f"{API_BASE_URL}/dvr/gameclips", headers=HEADERS).json().get('values'):
        clip_datetime = datetime.datetime.strptime(clip.get('uploadDate').split('.')[0], '%Y-%m-%dT%H:%M:%S')
        if clip_datetime < datetime.datetime(2023, 3, 18):
            continue
        clip_data = {
            'gamertag': os.environ.get('USERNAMES'),
            'uri': clip.get('contentLocators')[0].get('uri'),
            'game': clip.get('titleName').replace('\u00ae', ''),
            'datetime': clip_datetime.replace(tzinfo=datetime.timezone.utc).astimezone(pytz.timezone('US/Central')),
        }
        clip_data['title'] = f"{clip_data.get('game')} - {clip_data.get('datetime').strftime('%m-%d-%Y %H:%M:%S')}"
        clips.append(clip_data)

    return clips


def download_capture(capture_data: dict) -> tuple:
    """ Download a specific capture """

    if DEBUG:
        print(f"\tDownloading capture: {capture_data.get('title')} ...")

    dl = requests.get(capture_data.get('uri'), stream=True)

    try:
        with open(f"{capture_data.get('title').replace(':', '')}.mp4", "wb") as download:
            for chunk in dl.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    download.write(chunk)
    except requests.exceptions.StreamConsumedError as e:
        return False, e

    return True, True


def upload_capture_to_youtube(youtube, capture_data) -> tuple:
    """ Upload a capture to YouTube and add to the given playlist """

    print(f"\tUploading capture: {capture_data.get('title')} ...")

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
            "playlistId": PLAYLIST_ID,
            "resourceId": {
              "kind": "youtube#video",
              "videoId": video_id
            }
          }
        }
    )

    request.execute()
    return True, True


@api.route("/process/")
def process(count: int = -1):
    """ Main function, processes everything """

    results = {'success': [], 'fail': []}

    youtube_api = auth_youtube()
    existing = get_last_playlist_items(youtube_api)

    if DEBUG and not existing:
        print("Quota exceeded, stopping operation.")
        return

    captures = get_xbox_capture_list()

    for capture in captures:

        if capture.get('title') in existing:
            continue

        success, message = download_capture(capture)

        if not success:
            results['fail'].append((capture.get('title'), f"error while downloading: {message}"))
            if message == 'quota':
                print("Quota exceeded, stopping operation.")
                return results, 403 if results.get('fail') else 200

        else:
            success, message = upload_capture_to_youtube(youtube_api, capture)

            if not success:
                results['fail'].append((capture.get('title'), f"error while uploading: {message}"))

            else:
                results['success'].append(capture.get('title'))

        os.remove(f"{capture.get('title').replace(':', '')}.mp4")

        if -1 < count < (len(results.get('fail')) + len(results.get('success'))):
            break

    print(f"\nUploads - Success: {len(results.get('success'))} Failed: {len(results.get('fail'))}")

    if DEBUG and results.get('success'):
        print("\nThe following videos uploaded successfully:")
        for title in results.get('success'):
            print(f"\t{title}")

    if results.get('fail'):
        print("\nThe following videos failed to upload:")
        for title, error in results.get('fail'):
            print(f"\t{title} - {error}")

    return results, 403 if results.get('fail') else 200


if __name__ == '__main__':
    api.run()
