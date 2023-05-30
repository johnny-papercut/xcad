import datetime
import os
import random
import string
import sys

import cv2
import flask
import google_auth_oauthlib.flow
import googleapiclient.discovery
import numpy
import pytz
import requests
from google.auth.transport.requests import Request
from google.cloud import bigquery
from google.cloud import storage
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from googleapiclient.errors import ResumableUploadError
from googleapiclient.http import MediaFileUpload, HttpError

import pafy

SETTINGS = {
    'debug': True,
    'xbox_api_base': 'https://xbl.io/api/v2',
    'profile_table': 'zirekyle-main.xcad.profiles',
    'profiles': {},
}

api = flask.Flask(__name__)
api.secret_key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'


def load_profiles():
    """ Load profile data from BigQuery """

    bq = initialize_bigquery_client()
    profiles = [profile for profile in bq.query(f"SELECT * FROM `{SETTINGS.get('profile_table')}`").result()]

    for profile in profiles:
        SETTINGS['profiles'][profile.xbox_gamertag] = {
            'xbox_api_key': profile.xbox_api_key,
            'youtube_playlist_id': profile.youtube_playlist_id,
            'youtube_win_playlist_id': profile.youtube_win_playlist_id,
            'youtube_client_id': profile.youtube_client_id,
            'youtube_client_secret': profile.youtube_client_secret,
            'youtube_token': profile.youtube_token,
            'youtube_refresh_token': profile.youtube_refresh_token,
            'screenshot_bucket_name': profile.screenshot_bucket_name,
        }


def save_credentials(profile: str, credentials: dict):
    """ Save credentials to BigQuery """

    bq = initialize_bigquery_client()
    bq.query(f"UPDATE `{SETTINGS.get('profile_table')}` "
             f"SET youtube_token = '{credentials.get('token')}', "
             f"youtube_refresh_token = '{credentials.get('refresh_token')}' "
             f"WHERE xbox_gamertag = '{profile}'")
    bq.close()


@api.route('/authorize/<string:profile>')
def authorize(profile: str):

    load_profiles()

    client_id = SETTINGS.get('profiles').get(profile).get('youtube_client_id')
    client_secret = SETTINGS.get('profiles').get(profile).get('youtube_client_secret')

    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        client_config={
            "web": {
                "client_id": client_id,
                "project_id": "zirekyle-main",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_secret": client_secret,
                "redirect_uris": [
                    "http://localhost:5000/oauth2callback/Zirekyle",
                    "https://xcad.zirekyle.com/oauth2callback/Zirekyle",
                    "https://xcad-akurivnfnq-uc.a.run.app/oauth2callback/Zirekyle"]
            }
        },
        scopes=['https://www.googleapis.com/auth/youtube']
    )

    flow.redirect_uri = f"{flask.url_for('oauth2callback', _external=True, profile=profile)}"
    print(flow.redirect_uri)

    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    flask.session['state'] = state

    return flask.redirect(authorization_url)


@api.route('/oauth2callback/<string:profile>')
def oauth2callback(profile: str):

    load_profiles()

    client_id = SETTINGS.get('profiles').get(profile).get('youtube_client_id')
    client_secret = SETTINGS.get('profiles').get(profile).get('youtube_client_secret')

    state = flask.session.get('state')

    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        client_config={
            "web": {
                "client_id": client_id,
                "project_id": "zirekyle-main",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_secret": client_secret,
                "redirect_uris": [
                    "http://localhost:5000/oauth2callback/Zirekyle",
                    "https://xcad.zirekyle.com/oauth2callback/Zirekyle",
                    "https://xcad-akurivnfnq-uc.a.run.app/oauth2callback/Zirekyle"]
            }
        },
        scopes=["https://www.googleapis.com/auth/youtube"], state=state)
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True, profile=profile)

    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    credentials = credentials_to_dict(flow.credentials)
    flask.session['credentials'] = credentials
    save_credentials(profile, credentials)
    return flask.redirect('/')


def initialize_bigquery_client():
    """ Initialize BQ client with local or implied credentials """

    if not os.path.exists('google.json'):
        return bigquery.Client()

    credentials = service_account.Credentials.from_service_account_file(
        'google.json', scopes=["https://www.googleapis.com/auth/cloud-platform"])

    return bigquery.Client(credentials=credentials)


def initialize_storage_client():
    """ Initialize Google Storage client with local or implied credentials """

    if not os.path.exists('google.json'):
        return storage.Client()

    credentials = service_account.Credentials.from_service_account_file('google.json')

    return storage.Client(credentials=credentials)


def initialize_youtube_client(profile: str):     # -> googleapiclient.discovery.Resource
    """ Authenticate to YouTube and return a YouTube API client connection """

    print(f"[Profile: {profile}] Authenticating to YouTube...")

    load_profiles()
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
    save_credentials(profile, credentials_to_dict(credentials))

    if not credentials.valid:
        print("INVALID CREDENTIALS!")
        return None

    return googleapiclient.discovery.build('youtube', 'v3', credentials=credentials)


def get_playlist_items(youtube, playlist_id: str) -> list:
    """ Get the titles of all YouTube videos in a playlist """

    items = []
    page_token = None

    while len(items) < 1 or page_token:

        try:
            response = youtube.playlistItems().list(
                part='contentDetails,snippet',
                playlistId=playlist_id,
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

            items.append((item.get('snippet').get('title'), item.get('contentDetails').get('videoId')))

    return items


def get_screenshot_bucket_list(storage_client, profile: str) -> list:

    if SETTINGS.get('debug'):
        print(f"[Profile: {profile}] Getting existing screenshot list...")

    settings = SETTINGS.get('profiles').get(profile)

    titles = []

    raw_list = [blob for blob in storage_client.list_blobs(settings.get('screenshot_bucket_name'))]

    for blob in raw_list:
        formatted = ' - '.join(blob.name.split(' - ')[0:-1])
        if formatted not in titles:
            titles.append(formatted)

    return titles


def get_screenshots(profile: str, kind: str = 'all') -> list:

    load_profiles()

    storage_client = initialize_storage_client()
    settings = SETTINGS.get('profiles').get(profile)

    screenshots = []

    for blob in storage_client.list_blobs(settings.get('screenshot_bucket_name')):

        blob_data = {
            'title': ' - '.join(blob.name.split(' - ')[0:-1]).replace('.png', ''),
            'filename': blob.name,
            'url': f"https://storage.googleapis.com/{settings.get('screenshot_bucket_name')}/{blob.name}",
            'game': ' - '.join(blob.name.split(' - ')[0:-2]),
            'datetime': datetime.datetime.strptime(blob.name.split(' - ')[-2], '%m-%d-%Y %H-%M-%S'),
            'kind': blob.name.split(' - ')[-1].replace('.png', '')
        }

        if kind == 'all' or blob_data.get('kind') == kind:
            screenshots.append(blob_data)

    return screenshots


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


def get_xbox_screenshot_list(profile: str) -> list:
    """ Get data about recent Xbox screenshots """

    if SETTINGS.get('debug'):
        print(f"[Profile: {profile}] Getting screenshot data from Xbox...")

    settings = SETTINGS.get('profiles').get(profile)
    headers = {'accept': '*/*', 'x-authorization': settings.get('xbox_api_key')}

    screenshots = []
    continuation = 'initial'

    while continuation:

        url = f"{SETTINGS.get('xbox_api_base')}/dvr/screenshots"

        if continuation and continuation != 'initial':
            url += f"?continuationToken={continuation}"

        response = requests.get(url, headers=headers).json()

        continuation = response.get('continuationToken')

        for screenshot in response.get('values'):

            dt = datetime.datetime.strptime(screenshot.get('captureDate').split('.')[0], '%Y-%m-%dT%H:%M:%SZ')

            data = {
                'gamertag': profile,
                'Full': screenshot.get('contentLocators')[0].get('uri'),
                'Thumbnail Small': screenshot.get('contentLocators')[1].get('uri'),
                'Thumbnail Large': screenshot.get('contentLocators')[2].get('uri'),
                'game': screenshot.get('titleName').replace('\u00ae', ''),
                'datetime': dt.replace(tzinfo=datetime.timezone.utc).astimezone(pytz.timezone('US/Central')),
            }

            if len(screenshot.get('contentLocators')) > 3:
                data['HDR'] = screenshot.get('contentLocators')[3].get('uri')

            data['title'] = f"{data.get('game')} - {data.get('datetime').strftime('%m-%d-%Y %H-%M-%S')}"
            screenshots.append(data)

    return sorted(screenshots, key=lambda x: x.get('datetime'))


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


def download_screenshots(screenshot_data: dict, profile: str) -> tuple:
    """ Download a collection of screenshot images """

    if SETTINGS.get('debug'):
        print(f"[Profile: {profile}] Downloading screenshot collection: {screenshot_data.get('title')} ...")

    for kind in ['Full', 'Thumbnail Small', 'Thumbnail Large', 'HDR']:

        if not screenshot_data.get(kind):
            continue

        url = screenshot_data.get(kind)

        dl = requests.get(url, stream=True)

        try:
            with open(f"{screenshot_data.get('title').replace(':', '')} - {kind}.png", "wb") as download:
                for chunk in dl.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        download.write(chunk)
        except requests.exceptions.StreamConsumedError as e:
            return False, e

    return True, True


def upload_screenshot(storage_client, filename: str, profile: str):
    """ Upload an individual screenshot file to Google Storage """

    if SETTINGS.get('debug'):
        print(f"[Profile: {profile}] Uploading screenshot: {filename} ...")

    bucket = storage_client.get_bucket(SETTINGS.get('profiles').get(profile).get('screenshot_bucket_name'))
    blob = bucket.blob(filename)
    blob.upload_from_filename(filename)
    blob.make_public()


def upload_capture_to_youtube(youtube, capture_data: dict, profile: str, dub: bool) -> tuple:
    """ Upload a capture to YouTube and add to the given playlist """

    print(f"[Profile: {profile}] Uploading capture: {capture_data.get('title')} ...")

    media = MediaFileUpload(f"{capture_data.get('title').replace(':', '')}.mp4", mimetype='video/mp4', resumable=True)

    request = youtube.videos().insert(
        part="snippet,status",
        body={
          "snippet": {
            "description": "This video was automatically uploaded from XCAD.",
            "title": capture_data.get('title'),
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

    add_to_youtube_playlist(youtube, SETTINGS.get('profiles').get(profile).get('youtube_playlist_id'), video_id)

    if dub:
        add_to_youtube_playlist(youtube, SETTINGS.get('profiles').get(profile).get('youtube_win_playlist_id'), video_id)

    return True, True


def add_to_youtube_playlist(youtube, playlist_id: str, video_id: str):
    """ Add the video ID to the YouTube playlist ID """

    youtube.playlistItems().insert(
        part="snippet",
        body={
            "snippet": {
                "playlistId": playlist_id,
                "resourceId": {
                    "kind": "youtube#video",
                    "videoId": video_id
                }
            }
        }
    ).execute()


def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }


def detect_dub(mode: str, video: str) -> bool:

    if mode == 'file':
        capture = cv2.VideoCapture(video)
    elif mode == 'url':
        video = pafy.new(video)
        best = video.getbest(preftype="mp4")
        capture = cv2.VideoCapture(best.url)
    else:
        return False

    match = cv2.imread('victory.png', 0)

    count = 0

    while True:

        count += 1

        if count % 60:
            capture.grab()
            continue

        success, image = capture.read()

        if not success:
            break

        grayscale = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

        if len(list(zip(*numpy.where(cv2.matchTemplate(grayscale, match, cv2.TM_CCOEFF_NORMED) >= 0.8)[::-1]))):
            return True

    return False


def check_playlist_for_dubs(profile: str):

    load_profiles()
    youtube = initialize_youtube_client(profile)

    playlist_id = SETTINGS.get('profiles').get(profile).get('youtube_playlist_id')
    win_playlist_id = SETTINGS.get('profiles').get(profile).get('youtube_win_playlist_id')

    existing_wins = [item[1] for item in get_playlist_items(youtube, win_playlist_id)]

    page_token = None

    while True:

        try:
            response = youtube.playlistItems().list(
                part='contentDetails,snippet',
                playlistId=playlist_id,
                maxResults=50,
                pageToken=page_token,
            ).execute()
        except HttpError:
            return []

        page_token = response.get('nextPageToken')

        for item in response.get('items'):

            if item.get('contentDetails').get('videoId') in existing_wins:
                continue

            url = f"https://youtube.com/watch?v={item.get('contentDetails').get('videoId')}"
            dub = detect_dub('url', url)

            if dub:
                add_to_youtube_playlist(youtube, win_playlist_id, item.get('contentDetails').get('videoId'))
                print(f"Adding dub: {url}")

        if not page_token:
            return


@api.route("/process/<string:profile>/<string:mode>/<int:count>")
def process_all(profile: str, mode: str, count: int):
    """ Process a specific count of videos """
    return process(profile, mode, count)


@api.route("/process/<string:profile>/<string:mode>")
def process_mode(profile: str, mode: str):
    """ Process a specific count of videos """
    return process(profile, mode)


@api.route("/process/<string:profile>")
def process_profile(profile: str):
    """ Process a specific count of videos """
    return process(profile)


@api.route("/process/")
def process(profile: str = '', mode: str = '', count: int = -1):
    """ Main function, processes everything """
    
    load_profiles()

    results = {'success': [], 'fail': []}

    if profile == 'all' or profile == '':
        profiles = SETTINGS.get('profiles').keys()
    else:
        profiles = [profile]

    if not mode:
        mode = 'all'

    print(f"Running XCAD with following parameters - "
          f"Profiles: {', '.join(profiles)} | Mode: {mode.title()} | Count: {'All' if count < 1 else count}")

    for profile in profiles:

        if mode in ['all', 'screens', 'screenshots']:
            storage_api = initialize_storage_client()
            existing = get_screenshot_bucket_list(storage_api, profile)
            screenshots = get_xbox_screenshot_list(profile)

        else:
            storage_api = None
            existing = []
            screenshots = []

        i = 0

        for screenshot in screenshots:

            if screenshot.get('title').replace(':', '') in existing:
                continue

            success, message = download_screenshots(screenshot, profile)

            if not success:
                results['fail'].append((profile, screenshot.get('title'), f"error while downloading: {message}"))

            else:

                for kind in ['Full', 'Thumbnail Small', 'Thumbnail Large', 'HDR']:

                    filename = f"{screenshot.get('title').replace(':', '')} - {kind}.png"

                    if not os.path.exists(filename):
                        continue

                    upload_screenshot(storage_api, filename, profile)

                    try:
                        os.remove(filename)
                    except PermissionError:
                        print(f"Failed to delete: {filename}")

            i += 1

            if -1 < count <= i:
                break

        playlist_id = SETTINGS.get('profiles').get(profile).get('youtube_playlist_id')
        win_playlist_id = SETTINGS.get('profiles').get(profile).get('youtube_win_playlist_id')

        if mode in ['all', 'videos', 'captures', 'backfill']:
            youtube_api = initialize_youtube_client(profile)

            if not youtube_api:
                return "YouTube authentication failure", 401

            existing = get_playlist_items(youtube_api, playlist_id)
            existing_wins = get_playlist_items(youtube_api, win_playlist_id)

            if SETTINGS.get('debug') and not existing:
                print("Quota exceeded, stopping operation.")
                return "Quota exceeded, stopping operation.", 200

            captures = get_xbox_capture_list(profile)

        else:
            youtube_api = None
            existing = []
            existing_wins = []
            captures = []

        for capture in captures:

            if capture.get('title') in [item[0] for item in existing] and mode != 'backfill':
                continue

            if mode == 'backfill' and 'Modern Warfare' not in capture.get('title'):
                continue

            if not os.path.exists(f"{capture.get('title').replace(':', '')}.mp4"):
                success, message = download_capture(capture, profile)
            else:
                success, message = True, 'True'

            if not success:
                results['fail'].append((profile, capture.get('title'), f"error while downloading: {message}"))

            else:

                dub = detect_dub("file", f"{capture.get('title').replace(':', '')}.mp4")

                if mode != 'backfill':
                    success, message = upload_capture_to_youtube(youtube_api, capture, profile, dub)
                elif dub:
                    for item in existing:
                        if item[0] == capture.get('title'):
                            if item[1] not in [i[0] for i in existing_wins]:
                                print(f"Adding dub to list: {capture.get('title')}")
                                add_to_youtube_playlist(youtube_api, win_playlist_id, item[1])
                    success, message = True, 'True'

                if not success:
                    results['fail'].append((profile, capture.get('title'), f"error while uploading: {message}"))
                    if message == 'quota':
                        break

                else:
                    results['success'].append((profile, capture.get('title')))

            try:
                os.remove(f"{capture.get('title').replace(':', '')}.mp4")
            except PermissionError:
                print(f"Failed to delete: {capture.get('title').replace(':', '')}.mp4")

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


@api.route("/zoom/<string:title>")
def zoom(title: str):
    """ Zoom to a single image """

    settings = SETTINGS.get('profiles').get('Zirekyle')
    url = f"https://storage.googleapis.com/{settings.get('screenshot_bucket_name')}/{title} - Full.png"

    return flask.render_template('zoom.html', title=title, url=url)


@api.route("/")
def index():
    """ Index page """

    page = flask.request.args.get('page') if 'page' in flask.request.args.keys() else 1
    sort = flask.request.args.get('sort') if 'sort' in flask.request.args.keys() else 'new'

    screenshots = sorted(
        get_screenshots('Zirekyle', 'Thumbnail Small'),
        key=lambda x: x.get('datetime'),
        reverse=sort == 'new'
    )[(int(page)-1)*50:int(page)*50]

    # for file in files:

    return flask.render_template('index.html', screenshots=screenshots)


if __name__ == '__main__':

    action = sys.argv[1] if len(sys.argv) > 1 else None
    arg_profile = sys.argv[2] if len(sys.argv) > 2 else 'all'
    arg_mode = sys.argv[3] if len(sys.argv) > 3 else 'all'
    arg_count = int(sys.argv[4]) if len(sys.argv) > 4 else -1

    match action:
        case 'process':
            process(arg_profile, arg_mode, arg_count)
        case 'backfill':
            check_playlist_for_dubs(arg_profile)
        case _:
            if action is not None:
                print(f"Unknown action: {action}")
            else:
                api.run()
