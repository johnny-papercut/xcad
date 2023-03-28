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
import google.cloud.logging
import logging


HEADERS = {'accept': '*/*', 'x-authorization': os.environ.get('XBL_API_KEY')}
API_BASE_URL = 'https://xbl.io/api/v2'
USERNAME = os.environ.get('USERNAME')
PLAYLIST_ID = os.environ.get('PLAYLIST_ID')

DEBUG = True
api = Flask(__name__)


def is_local() -> bool:
    """ Check if this is running locally or not """
    return os.path.exists('credentials.json')


def auth_youtube():     # -> googleapiclient.discovery.Resource
    """ Authenticate to YouTube and return a YouTube API client connection """

    if DEBUG:
        logging.info("Authenticating to YouTube...")

    credentials = None

    if is_local:

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

    else:

        return googleapiclient.discovery.build('youtube', 'v3')


def get_last_playlist_items(youtube) -> list:
    """ Get the titles of the last 50 YouTube playlist videos """

    if DEBUG:
        logging.info("Getting playlist titles from YouTube...")

    titles = []
    page_token = None

    while len(titles) < 1 or page_token:

        try:
            response = youtube.playlistItems().list(
                part='contentDetails,snippet',
                playlistId=os.environ.get('PLAYLIST_ID'),
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
        logging.info("Getting capture data from Xbox...")

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

    return sorted(clips, key=lambda x: x.get('datetime'))


def download_capture(capture_data: dict) -> tuple:
    """ Download a specific capture """

    if DEBUG:
        logging.info(f"Downloading capture: {capture_data.get('title')} ...")

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

    logging.info(f"Uploading capture: {capture_data.get('title')} ...")

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


@api.route("/process/<int:count>")
def process_count(count: int):
    """ Process a specific count of videos """
    return process(count)


@api.route("/process/")
def process(count: int = -1):
    """ Main function, processes everything """

    results = {'success': [], 'fail': []}

    if count != -1:
        logging.info(f"Running XCAD for {count} video{'s' if count != 1 else ''}...")
    else:
        logging.info("Running XCAD for all videos (before exceeding quota)...")

    youtube_api = auth_youtube()
    existing = get_last_playlist_items(youtube_api)

    if DEBUG and not existing:
        logging.warning("Quota exceeded, stopping operation.")
        return

    captures = get_xbox_capture_list()

    for capture in captures:

        if capture.get('title') in existing:
            continue

        success, message = download_capture(capture)

        if not success:
            results['fail'].append((capture.get('title'), f"error while downloading: {message}"))
            if message == 'quota':
                logging.warning("Quota exceeded, stopping operation.")
                return results, 403 if results.get('fail') else 200

        else:
            success, message = upload_capture_to_youtube(youtube_api, capture)

            if not success:
                results['fail'].append((capture.get('title'), f"error while uploading: {message}"))

            else:
                results['success'].append(capture.get('title'))

        os.remove(f"{capture.get('title').replace(':', '')}.mp4")

        if -1 < count <= (len(results.get('fail')) + len(results.get('success'))):
            break

    logging.info(f"Uploads - Success: {len(results.get('success'))} Failed: {len(results.get('fail'))}")

    if DEBUG and results.get('success'):
        logging.info("The following videos uploaded successfully:")
        for title in results.get('success'):
            logging.info(f"{title}")

    if results.get('fail'):
        logging.info("The following videos failed to upload:")
        for title, error in results.get('fail'):
            logging.warning(f"{title} - {error}")

    return results, 403 if results.get('fail') else 200


if __name__ == '__main__':

    logging.basicConfig(level=logging.INFO)

    if not is_local():
        client = google.cloud.logging.Client()
        client.setup_logging()

    api.run()
