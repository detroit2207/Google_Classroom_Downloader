#!/usr/bin/env python3
"""
Google Classroom Downloader for Electron
Downloads all materials from a Classroom course into structured folders.
"""

import os
import sys
import re
import io
import json
import time
import socket
import base64
import requests

from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.errors import HttpError

from cryptography.fernet import Fernet

import os
import sys

class Logger:
    def __init__(self, filename):
        self.terminal = sys.stdout  # for stdout, will replace later with sys.stderr for stderr
        self.log = open(filename, "a", encoding="utf-8")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        self.terminal.flush()
        self.log.flush()

log_file_path = os.path.join(os.getcwd(), "downloader.log")

# Redirect stdout and stderr separately, with separate Logger instances:
sys.stdout = Logger(log_file_path)
sys.stderr = Logger(log_file_path)



from dotenv import load_dotenv
import os

load_dotenv()  # loads variables from .env into os.environ

# Scopes
SCOPES = [
    'https://www.googleapis.com/auth/classroom.courses.readonly',
    'https://www.googleapis.com/auth/classroom.courseworkmaterials.readonly',
    'https://www.googleapis.com/auth/classroom.announcements.readonly',
    'https://www.googleapis.com/auth/classroom.student-submissions.me.readonly',
    'https://www.googleapis.com/auth/classroom.topics.readonly',
    'https://www.googleapis.com/auth/drive.readonly'
]


def safe_execute(request, description="request"):
    while True:
        try:
            return request.execute()
        except (socket.gaierror, HttpError, Exception) as e:
            print(f" Network issue during {description}: {e}")
            print(" Retrying in 5 seconds...")
            time.sleep(5)


def get_token_path():
    """Token path in USER_DATA_PATH or current dir"""
    base = os.environ.get("USER_DATA_PATH", os.getcwd())
    os.makedirs(base, exist_ok=True)
    print(f"Token path: {base}")
    return os.path.join(base, "token.json")


def get_credentials_path():
    base_dir = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    creds_path = os.path.join(base_dir, "resources", "credentials.json")
    if not os.path.exists(creds_path):  # fallback for dev mode
        creds_path = os.path.join(os.getcwd(), 'resources', 'app.asar.unpacked', 'resources', "credentials.json")
    print(creds_path)
    return creds_path


# Back4App / Fernet config (set these as env vars in production)
BACK4APP_APP_ID = os.getenv("BACK4APP_APP_ID")
BACK4APP_MASTER_KEY = os.getenv("BACK4APP_MASTER_KEY")
BACK4APP_API_KEY = os.getenv("BACK4APP_API_KEY")

# IMPORTANT: Put the exact Fernet key used to encrypt credentials.json here or via env var.
# A valid Fernet key is 44 chars (e.g. 'OYlXrJQbyQ8OKYoOkD6DgGyHhBglsOn55TfCEpFvQoA=')
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")


def load_and_decrypt_credentials():
    """
    Fetch encrypted credentials JSON string from Back4App and decrypt using Fernet key.
    Returns: parsed JSON dict (client_config) suitable for from_client_config().
    """
    if not ENCRYPTION_KEY:
        raise RuntimeError("ENCRYPTION_KEY is not set. Set environment variable ENCRYPTION_KEY to the Fernet key used when encrypting credentials.json")

    # Validate basic Fernet key length
    if len(ENCRYPTION_KEY) not in (44, 43):  # sometimes trailing padding omitted — we'll rely on Fernet for final check
        # still try, but warn
        print("WARNING: ENCRYPTION_KEY length looks unusual; make sure it's the original Fernet key.")

    url = "https://parseapi.back4app.com/functions/getEncryptedCredentials"
    headers = {
        "X-Parse-Application-Id": BACK4APP_APP_ID,
        "X-Parse-Master-Key": BACK4APP_MASTER_KEY,
        "x-api-key": BACK4APP_API_KEY,
        "Content-Type": "application/json"
    }

    resp = requests.post(url, headers=headers)
    if resp.status_code != 200:
        raise Exception(f"Failed to fetch credentials: {resp.status_code} - {resp.text}")

    result = resp.json().get("result")
    print(f"DEBUG: Response from Back4App: {result}")
    if not result or "encryptedData" not in result:
        raise Exception("No 'encryptedData' found in Back4App response")

    encrypted_token = result["encryptedData"]
    # encrypted_token should be the string produced by fernet.encrypt(...) (a URL-safe base64 token)
    f = Fernet(ENCRYPTION_KEY.encode())
    try:
        decrypted_bytes = f.decrypt(encrypted_token.encode())
    except Exception as e:
        raise Exception(f"Failed to decrypt data (check ENCRYPTION_KEY matches the key used to encrypt): {e}")

    # parse JSON and return as dict for InstalledAppFlow.from_client_config
    try:
        client_config = json.loads(decrypted_bytes.decode("utf-8"))
    except Exception as e:
        raise Exception(f"Decrypted data is not valid JSON: {e}")

    return client_config


def extract_course_id(link_or_id):
    """Decode base64 Classroom course ID"""
    try:
        if re.fullmatch(r"\d{6,}", link_or_id):
            return link_or_id
        m = re.search(r"/c/([A-Za-z0-9_\-]+)", link_or_id)
        if m:
            encoded = m.group(1)
            padding = '=' * (-len(encoded) % 4)
            decoded = base64.b64decode(encoded + padding).decode("utf-8")
            return decoded
        return link_or_id
    except Exception as e:
        raise ValueError(f"Failed to extract course id from '{link_or_id}': {e}")


def safe_name(name):
    """Sanitize file/folder names for Windows"""
    name = re.sub(r'[<>:"/\\|?*\n]', '', name)
    name = name.strip()
    return name[:500] if len(name) > 500 else name


def get_folder_name(parent_title=None, announcement_text=None):
    """Folder naming priority"""
    if parent_title:
        return safe_name(parent_title)
    elif announcement_text:
        return safe_name(announcement_text[:50])
    return "Other Materials"


def download_drive_file(file_id, file_path, drive_service, total_files=None, current_index=None):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    # If already exists → skip but still update progress
    if os.path.exists(file_path):
        if total_files and current_index:
            overall_progress = int((current_index) / total_files * 100)
            print(f"OverallProgress: {overall_progress}% for {os.path.basename(file_path)} (File {current_index}/{total_files})", flush=True)
        print(f"Skipped: {file_path}", flush=True)
        return

    request = drive_service.files().get_media(fileId=file_id)
    fh = io.FileIO(file_path, 'wb')
    downloader = MediaIoBaseDownload(fh, request)

    done = False
    while not done:
        status, done = downloader.next_chunk()
        if status and total_files is not None and current_index is not None:
            overall_progress = int(((current_index - 1) + status.progress()) / total_files * 100)
            print(f"OverallProgress: {overall_progress}% for {os.path.basename(file_path)} (File {current_index}/{total_files})", flush=True)

    print(f"Downloaded: {file_path}", flush=True)


def download_from_drive_folder(drive_service, folder_id, out_dir, total_files, current_index):
    os.makedirs(out_dir, exist_ok=True)
    query = f"'{folder_id}' in parents and trashed = false"
    while True:
        resp = drive_service.files().list(q=query, fields="nextPageToken, files(id, name, mimeType)").execute()
        files = resp.get("files", [])
        for f in files:
            if f.get("mimeType") == "application/vnd.google-apps.folder":
                subdir = os.path.join(out_dir, safe_name(f.get("name", f["id"])))
                current_index = download_from_drive_folder(drive_service, f["id"], subdir, total_files, current_index)
            else:
                dest = os.path.join(out_dir, safe_name(f.get("name", f["id"])))
                download_drive_file(f["id"], dest, drive_service, total_files, current_index)
                current_index += 1
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    return current_index


def count_files_in_drive_folder(drive_service, folder_id):
    query = f"'{folder_id}' in parents and trashed = false"
    total = 0
    while True:
        resp = drive_service.files().list(q=query, fields="nextPageToken, files(id, mimeType)").execute()
        files = resp.get("files", [])
        for f in files:
            if f.get("mimeType") == "application/vnd.google-apps.folder":
                total += count_files_in_drive_folder(drive_service, f["id"])
            else:
                total += 1
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    return total


def count_total_files(classroom_service, drive_service, course_id):
    total = 0

    anns = classroom_service.courses().announcements().list(courseId=course_id).execute().get("announcements", [])
    for a in anns:
        for m in a.get("materials", []):
            if "driveFile" in m:
                df = m["driveFile"]["driveFile"]
                if df.get("mimeType") == "application/vnd.google-apps.folder":
                    total += count_files_in_drive_folder(drive_service, df["id"])
                else:
                    total += 1

    mats = classroom_service.courses().courseWorkMaterials().list(courseId=course_id).execute().get("courseWorkMaterial", [])
    for mat in mats:
        for m in mat.get("materials", []):
            if "driveFile" in m:
                df = m["driveFile"]["driveFile"]
                if df.get("mimeType") == "application/vnd.google-apps.folder":
                    total += count_files_in_drive_folder(drive_service, df["id"])
                else:
                    total += 1

    works = classroom_service.courses().courseWork().list(courseId=course_id).execute().get("courseWork", [])
    for w in works:
        for m in w.get("materials", []):
            if "driveFile" in m:
                df = m["driveFile"]["driveFile"]
                if df.get("mimeType") == "application/vnd.google-apps.folder":
                    total += count_files_in_drive_folder(drive_service, df["id"])
                else:
                    total += 1

    return max(total, 1)


def fix_extension_if_missing(filename, mime_type):
    root, ext = os.path.splitext(filename)
    if ext == "":
        ext_map = {
            "application/pdf": ".pdf",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
        }
        if mime_type in ext_map:
            return filename + ext_map[mime_type]
        else:
            print(f"Warning: file '{filename}' has no extension and unknown mimeType '{mime_type}'")
    return filename


def download_classroom(classroom_link, output_dir=None):
    creds = authenticate()
    classroom_service = build("classroom", "v1", credentials=creds)
    drive_service = build("drive", "v3", credentials=creds)

    course_id = extract_course_id(classroom_link)
    course = classroom_service.courses().get(id=course_id).execute()
    print("DEBUG course data:", course)
    course_name = safe_name(course.get("name", f"course_{course_id}"))

    if not output_dir:
        output_dir = os.getcwd()
    out_root = os.path.join(output_dir, course_name)
    os.makedirs(out_root, exist_ok=True)

    total_files = count_total_files(classroom_service, drive_service, course_id)
    current_index = 1

    anns_resp = safe_execute(classroom_service.courses().announcements().list(courseId=course_id))
    anns = anns_resp.get("announcements", [])
    for a in anns:
        materials = a.get("materials", [])
        if not materials:
            continue
        folder_dir = os.path.join(out_root, get_folder_name(a.get("title"), a.get("text")))
        os.makedirs(folder_dir, exist_ok=True)
        for m in materials:
            if "driveFile" in m:
                df = m["driveFile"]["driveFile"]
                if df.get("mimeType") == "application/vnd.google-apps.folder":
                    current_index = download_from_drive_folder(drive_service, df["id"], folder_dir, total_files, current_index)
                else:
                    dest_filename = safe_name(df.get("title") or df.get("name") or df["id"])
                    dest_filename = fix_extension_if_missing(dest_filename, df.get("mimeType", ""))
                    dest = os.path.join(folder_dir, dest_filename)
                    download_drive_file(df["id"], dest, drive_service, total_files, current_index)
                    current_index += 1

    mats_resp = safe_execute(classroom_service.courses().courseWorkMaterials().list(courseId=course_id))
    mats = mats_resp.get("courseWorkMaterial", [])
    for mat in mats:
        folder_dir = os.path.join(out_root, get_folder_name(mat.get("title")))
        os.makedirs(folder_dir, exist_ok=True)
        for m in mat.get("materials", []):
            if "driveFile" in m:
                df = m["driveFile"]["driveFile"]
                if df.get("mimeType") == "application/vnd.google-apps.folder":
                    current_index = download_from_drive_folder(drive_service, df["id"], folder_dir, total_files, current_index)
                else:
                    dest_filename = safe_name(df.get("title") or df.get("name") or df["id"])
                    dest_filename = fix_extension_if_missing(dest_filename, df.get("mimeType", ""))
                    dest = os.path.join(folder_dir, dest_filename)
                    download_drive_file(df["id"], dest, drive_service, total_files, current_index)
                    current_index += 1

    works_resp = safe_execute(classroom_service.courses().courseWork().list(courseId=course_id))
    works = works_resp.get("courseWork", [])
    for w in works:
        folder_dir = os.path.join(out_root, get_folder_name(w.get("title")))
        os.makedirs(folder_dir, exist_ok=True)
        for m in w.get("materials", []):
            if "driveFile" in m:
                df = m["driveFile"]["driveFile"]
                if df.get("mimeType") == "application/vnd.google-apps.folder":
                    current_index = download_from_drive_folder(drive_service, df["id"], folder_dir, total_files, current_index)
                else:
                    dest_filename = safe_name(df.get("title") or df.get("name") or df["id"])
                    dest_filename = fix_extension_if_missing(dest_filename, df.get("mimeType", ""))
                    dest = os.path.join(folder_dir, dest_filename)
                    download_drive_file(df["id"], dest, drive_service, total_files, current_index)
                    current_index += 1

    print(f"DISTRIBUTED_TOTAL::{total_files}")
    print(f"DOWNLOAD_SUCCESS::{os.path.abspath(out_root)}")
    sys.stdout.flush()


def authenticate():
    token_path = get_token_path()
    creds = None
    if os.path.exists(token_path):
        try:
            creds = Credentials.from_authorized_user_file(token_path, SCOPES)
        except Exception:
            creds = None
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception:
                creds = None
        if not creds:
            # Get client config (decrypted) as a dict
            client_config = load_and_decrypt_credentials()
            flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(token_path, "w", encoding="utf-8") as f:
            f.write(creds.to_json())
    return creds


def main():
    if "--get-total-files" in sys.argv:
        idx = sys.argv.index("--get-total-files")
        link = sys.argv[idx + 1]
        creds = authenticate()
        classroom_service = build("classroom", "v1", credentials=creds)
        drive_service = build("drive", "v3", credentials=creds)
        cid = extract_course_id(link)
        total = count_total_files(classroom_service, drive_service, cid)
        print(total)
        sys.exit(0)

    if len(sys.argv) >= 2:
        link = sys.argv[1]
        out = sys.argv[2] if len(sys.argv) >= 3 else None
        download_classroom(link, out)
    else:
        print("Usage: python downloader.py <classroom_link> [output_dir]")
        sys.exit(1)


if __name__ == "__main__":
    main()
