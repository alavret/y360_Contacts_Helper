import csv
import sys
import json
import logging
import logging.handlers as handlers
import os
import re
import time
from typing import Iterable, List
from dataclasses import dataclass
from http import HTTPStatus
from datetime import datetime

import requests
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth
from urllib.parse import urljoin

DEFAULT_360_API_URL = "https://api360.yandex.net"
CARDDAV_BASE_URL = "https://carddav.yandex.ru/addressbook"
DEFAULT_OAUTH_API_URL = "https://oauth.yandex.ru/token"
ITEMS_PER_PAGE = 100
MAX_RETRIES = 3
LOG_FILE = "y360_contacts.log"
RETRIES_DELAY_SEC = 2
SLEEP_TIME_BETWEEN_API_CALLS = 0.5

# MAX value is 1000
USERS_PER_PAGE_FROM_API = 1000
DEPARTMENTS_PER_PAGE_FROM_API = 100
GROUPS_PER_PAGE_FROM_API = 1000
ALL_USERS_REFRESH_IN_MINUTES = 15

EXIT_CODE = 1

# Необходимые права доступа для работы скрипта
NEEDED_PERMISSIONS = [
    "directory:read_users",
    "ya360_admin:mail_read_user_settings",
    "ya360_admin:mail_write_user_settings",
]

logger = logging.getLogger(LOG_FILE)
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
#file_handler = handlers.TimedRotatingFileHandler(LOG_FILE, when='D', interval=1, backupCount=30, encoding='utf-8')
file_handler = handlers.RotatingFileHandler(LOG_FILE, maxBytes=1024 * 1024 * 10,  backupCount=5, encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logger.addHandler(console_handler)
logger.addHandler(file_handler)

@dataclass
class SettingParams:
    oauth_token: str
    org_id: int
    users_file : str
    dry_run : bool
    service_app_id : str
    service_app_secret : str
    all_users : list
    all_users_get_timestamp : datetime
    vcard_folder : str
    contacts_collect_file : str
    all_users_file : str
    

def get_settings():
    exit_flag = False
    oauth_token_bad = False
    settings = SettingParams (
        users_file = os.environ.get("USERS_FILE","users.csv"),
        oauth_token = os.environ.get("OAUTH_TOKEN"),
        org_id = os.environ.get("ORG_ID"),
        dry_run = os.environ.get("DRY_RUN","false").lower() == "true",
        service_app_id = os.environ.get("SERVICE_APP_ID"),
        service_app_secret = os.environ.get("SERVICE_APP_SECRET"),
        all_users = [],
        all_users_get_timestamp = datetime.now(),
        vcard_folder = os.environ.get("VCARD_FOLDER","vcard"),
        contacts_collect_file = os.environ.get("CONTACT_COLLECT_STATUS_BASE_NAME","collect_status"),
        all_users_file = os.environ.get("USERS_FILE","users.csv"),
    )

    if not settings.users_file:
        logger.error("USERS_FILE не установлен.")
        exit_flag = True
    
    if not settings.oauth_token:
        logger.error("OAUTH_TOKEN не установлен.")
        oauth_token_bad = True

    if not settings.org_id:
        logger.error("ORG_ID не установлен.")
        exit_flag = True

    if not (oauth_token_bad or exit_flag):
        hard_error, result_ok = check_token_permissions(settings.oauth_token, settings.org_id, NEEDED_PERMISSIONS)
        if hard_error:
            logger.error("OAUTH_TOKEN не является действительным или не имеет необходимых прав доступа")
            oauth_token_bad = True
        elif not result_ok:
            print("ВНИМАНИЕ: Функциональность скрипта может быть ограничена. Возможны ошибки при работе с API.")
            print("=" * 100)
            input("Нажмите Enter для продолжения..")

    if not settings.service_app_id:
        logger.error("SERVICE_APP_ID не установлен.")
        exit_flag = True

    if not settings.service_app_secret:
        logger.error("SERVICE_APP_SECRET не установлен.")
        exit_flag = True

    if oauth_token_bad:
        exit_flag = True
    
    if exit_flag:
        return None
    
    return settings


def check_oauth_token(oauth_token, org_id):
    """Проверяет, что токен OAuth действителен."""
    url = f'{DEFAULT_360_API_URL}/directory/v1/org/{org_id}/users?perPage=100'
    headers = {
        'Authorization': f'OAuth {oauth_token}'
    }
    response = requests.get(url, headers=headers)
    if response.status_code == HTTPStatus.OK:
        return True
    return False


def check_token_permissions(token: str, org_id: int, needed_permissions: list) -> bool:
    """
    Проверяет права доступа для заданного токена.
    
    Args:
        token: OAuth токен для проверки
        org_id: ID организации
        needed_permissions: Список необходимых прав доступа
        
    Returns:
        bool: True если токен невалидный, False в противном случае, продолжение работы невозможно
        bool: True если все права присутствуют и org_id совпадает, False в противном случае, продолжение работы возможно
    """
    url = 'https://api360.yandex.net/whoami'
    headers = {
        'Authorization': f'OAuth {token}'
    }
    hard_error = False
    try:
        response = requests.get(url, headers=headers)
        
        # Проверка валидности токена
        if response.status_code != HTTPStatus.OK:
            logger.error(f"Невалидный токен. Статус код: {response.status_code}")
            if response.status_code == 401:
                logger.error("Токен недействителен или истек срок его действия.")
            else:
                logger.error(f"Ошибка при проверке токена: {response.text}")
            return True, False
        
        data = response.json()
        
        # Извлечение scopes и orgIds из ответа
        token_scopes = data.get('scopes', [])
        token_org_ids = data.get('orgIds', [])
        login = data.get('login', 'unknown')
        
        logger.info(f"Проверка прав доступа для токена пользователя: {login}")
        logger.debug(f"Доступные права: {token_scopes}")
        logger.debug(f"Доступные организации: {token_org_ids}")
        
        # Проверка наличия org_id в списке доступных организаций
        if str(org_id) not in [str(org) for org in token_org_ids]:
            logger.error("=" * 100)
            logger.error(f"ОШИБКА: Токен не имеет доступа к организации с ID {org_id}")
            logger.error(f"Доступные организации для этого токена: {token_org_ids}")
            logger.error("=" * 100)
            return True, False

        # Проверка наличия всех необходимых прав
        missing_permissions = []
        for permission in needed_permissions:
            if permission not in token_scopes:
                missing_permissions.append(permission)
        
        if missing_permissions:
            logger.error("=" * 100)
            logger.error("ОШИБКА: У токена отсутствуют необходимые права доступа!")
            logger.error("Недостающие права:")
            for perm in missing_permissions:
                logger.error(f"  - {perm}")
            logger.error("=" * 100)
            return False, False

        logger.info("✓ Все необходимые права доступа присутствуют")
        logger.info(f"✓ Доступ к организации {org_id} подтвержден")
        return False, True
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка при выполнении запроса к API: {e}")
        return True, False
    except json.JSONDecodeError as e:
        logger.error(f"Ошибка при парсинге ответа от API: {e}")
        return True, False
    except Exception as e:
        logger.error(f"Неожиданная ошибка при проверке прав доступа: {type(e).__name__}: {e}")
        return True, False


class TokenError(RuntimeError):
    pass


def get_service_app_token(settings: "SettingParams", user_email: str) -> str:
    """Request OAuth token for a specific user via service application."""
    client_id = settings.service_app_id
    client_secret = settings.service_app_secret

    if not client_id or not client_secret:
        raise TokenError("SERVICE_APP_CLIENT_ID and SERVICE_APP_CLIENT_SECRET must be set")

    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": client_id,
        "client_secret": client_secret,
        "subject_token": user_email,
        "subject_token_type": "urn:yandex:params:oauth:token-type:email",
    }

    try:
        response = requests.post(DEFAULT_OAUTH_API_URL, data=data, timeout=30)
    except requests.RequestException as exc:
        raise TokenError(f"Failed to request token: {exc}") from exc

    if not response.ok:
        raise TokenError(
            f"Token request failed for {user_email}: {response.status_code} {response.text}"
        )

    payload = response.json()
    access_token = payload.get("access_token")
    if not access_token:
        raise TokenError(f"No access_token in response for {user_email}: {payload}")
    return access_token


def read_users_csv(path: str) -> List[dict]:
    """Read users from CSV. Expects column 'Email' (case-insensitive)."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Users file not found: {path}")

    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    data_list = []
    for row in rows:
        # Normalize possible keys like email/Email
        email = row.get("Email") or row.get("email") or row.get("EMAIL")
        if email:
            data_list.append(email.strip().lower())
    return data_list


def discover_addressbooks(addressbook_home_url: str, session: requests.Session) -> list[dict]:
    """Discover all available addressbooks from CardDAV addressbook home URL."""
    from xml.etree import ElementTree as ET

    propfind_books = """<?xml version='1.0'?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:resourcetype />
    <D:displayname />
  </D:prop>
</D:propfind>"""

    try:
        logger.debug(f"Requesting PROPFIND {addressbook_home_url}, Method: PROPFIND")
        logger.debug(f"Headers: {session.headers}")
        logger.debug(f"Data: {propfind_books}")
        retries = 1
        while True:
            response = session.request(
                "PROPFIND",
                addressbook_home_url,
                headers={"Depth": "1", "Content-Type": "application/xml; charset=utf-8"},
                data=propfind_books,
                timeout=30,
            )
            logger.debug(f"Response: {response.status_code} {response.text}")
            if response.status_code not in (200, 207):
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Failed to PROPFIND addressbook home {addressbook_home_url}: {response.status_code} {response.text}")
                    return []
            else:
                break
    except requests.RequestException as exc:
        logger.error(f"Failed to PROPFIND addressbook home {addressbook_home_url}: {exc}")
        return []

    if response.status_code not in (200, 207):
        logger.error(
            f"PROPFIND {addressbook_home_url} failed: {response.status_code} {response.text}"
        )
        return []

    root = ET.fromstring(response.content)
    ns_full = {"D": "DAV:", "E": "urn:ietf:params:xml:ns:carddav"}

    addressbooks = []
    for resp in root.findall("D:response", ns_full):
        resourcetype = resp.find(".//D:resourcetype", ns_full)
        if resourcetype is None or resourcetype.find("E:addressbook", ns_full) is None:
            continue

        href_elem = resp.find("D:href", ns_full)
        displayname_elem = resp.find(".//D:displayname", ns_full)

        if href_elem is None or not href_elem.text:
            continue

        href_text = href_elem.text
        if href_text.startswith("http"):
            book_url = href_text
        else:
            book_url = urljoin(addressbook_home_url, href_text)

        book_name = (
            displayname_elem.text if displayname_elem is not None and displayname_elem.text else "Unknown"
        )
        addressbooks.append({"url": book_url, "name": book_name})

    return addressbooks


def _list_vcard_hrefs(addressbook_url: str, session: requests.Session) -> Iterable[str]:
    """Return hrefs of all vCards in an addressbook."""
    from xml.etree import ElementTree as ET

    propfind_body = """<?xml version='1.0'?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:getetag/>
    <D:getcontenttype/>
  </D:prop>
</D:propfind>"""

    try:
        logger.debug(f"Requesting PROPFIND {addressbook_url}, Method: PROPFIND")
        logger.debug(f"Headers: {session.headers}")
        logger.debug(f"Data: {propfind_body}")
        retries = 1
        while True:
            response = session.request(
                "PROPFIND",
                addressbook_url,
                headers={"Depth": "1", "Content-Type": "application/xml; charset=utf-8"},
                data=propfind_body,
                timeout=30,
            )
            logger.debug(f"Response: {response.status_code} {response.text}")
            if response.status_code not in (200, 207):
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Failed to PROPFIND {addressbook_url}: {response.status_code} {response.text}")
                    return []
            else:
                break
    except requests.RequestException as exc:
        logger.error(f"Failed to PROPFIND {addressbook_url}: {exc}")
        return []

    if response.status_code not in (200, 207):
        logger.error(
            f"PROPFIND {addressbook_url} failed: {response.status_code} {response.text}"
        )
        return []

    root = ET.fromstring(response.content)
    ns = {"D": "DAV:"}

    vcard_hrefs = []
    for resp in root.findall("D:response", ns):
        contenttype = resp.find(".//D:getcontenttype", ns)
        if contenttype is not None and contenttype.text and "vcard" in contenttype.text.lower():
            href_elem = resp.find("D:href", ns)
            if href_elem is not None and href_elem.text:
                vcard_hrefs.append(href_elem.text)
    return vcard_hrefs


def _fetch_vcards_with_data(addressbook_url: str, hrefs: Iterable[str], session: requests.Session) -> list[dict]:
    """Fetch full vCard bodies for provided hrefs using addressbook-multiget."""
    from xml.etree import ElementTree as ET

    hrefs_list = list(hrefs)
    if not hrefs_list:
        return []

    href_elements = "\n".join([f"<D:href>{href}</D:href>" for href in hrefs_list])
    multiget_body = f"""<?xml version="1.0" encoding="utf-8" ?>
        <A:addressbook-multiget xmlns:D="DAV:" xmlns:A="urn:ietf:params:xml:ns:carddav">
        <D:prop>
            <D:getetag/>
            <D:getcontenttype/>
            <A:address-data/>
        </D:prop>
        {href_elements}
        </A:addressbook-multiget>"""

    try:
        logger.debug(f"Requesting REPORT {addressbook_url}, Method: REPORT")
        logger.debug(f"Headers: {session.headers}")
        logger.debug(f"Data: {multiget_body}")
        retries = 1
        while True:
            response = session.request(
                "REPORT",
                addressbook_url,
                headers={"Depth": "1", "Content-Type": "application/xml; charset=utf-8"},
                data=multiget_body,
                timeout=60,
            )
            logger.debug(f"Response: {response.status_code} {response.text}")
            if response.status_code not in (200, 207):
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Failed to REPORT {addressbook_url}: {response.status_code} {response.text}")
                    return []
            else:
                break

    except requests.RequestException as exc:
        logger.error(f"Failed to REPORT {addressbook_url}: {exc}")
        return []

    if response.status_code not in (200, 207):
        logger.error(
            f"REPORT {addressbook_url} failed: {response.status_code} {response.text}"
        )
        return []

    ns_full = {"D": "DAV:", "E": "urn:ietf:params:xml:ns:carddav"}
    try:
        root = ET.fromstring(response.content)
    except ET.ParseError as exc:
        logger.error(f"Cannot parse addressbook-multiget response: {exc}")
        return []

    vcards = []
    for resp in root.findall("D:response", ns_full):
        address_data = resp.find(".//E:address-data", ns_full)
        href_elem = resp.find("D:href", ns_full)
        etag_elem = resp.find(".//D:getetag", ns_full)
        if (
            address_data is None
            or address_data.text is None
            or href_elem is None
            or not href_elem.text
        ):
            continue
        contact_url = urljoin(addressbook_url, href_elem.text)
        vcards.append(
            {
                "url": contact_url,
                "data": address_data.text,
                "etag": etag_elem.text if etag_elem is not None else None,
            }
        )
    return vcards


def _extract_emails_from_vcard_text(vcard_text: str) -> list[str]:
    """Return email values from raw vCard text by scanning EMAIL lines."""
    emails = []
    for raw_line in vcard_text.splitlines():
        line = raw_line.strip()
        if not line or not line.upper().startswith("EMAIL"):
            continue
        if ":" not in line:
            continue
        value = line.split(":", 1)[1].strip()
        if value:
            emails.append(value.lower())
    return emails


def _remove_emails_from_vcard(vcard_text: str, emails_to_remove: set[str]) -> str:
    """Remove EMAIL lines from vCard text that match provided email values."""
    email_line_pattern = re.compile(r"^EMAIL[;=\w-]*:(?P<email>.+)$", re.IGNORECASE)
    lines = vcard_text.splitlines()
    filtered_lines: list[str] = []

    for line in lines:
        match = email_line_pattern.match(line)
        if match:
            email_value = match.group("email").strip().lower()
            if email_value in emails_to_remove:
                continue
        filtered_lines.append(line)

    newline = "\r\n" if "\r\n" in vcard_text else "\n"
    return newline.join(filtered_lines)


def _replace_emails_in_vcard(
    vcard_text: str, search_template: str, replace_template: str
) -> tuple[str, int]:
    """
    Replace EMAIL values in vCard according to templates.
    Returns updated vCard text and number of replacements.
    """
    email_line_pattern = re.compile(
        r"^(EMAIL[;=\w-]*:)(?P<email>.+)$", re.IGNORECASE
    )
    lines = vcard_text.splitlines()
    replaced_count = 0
    new_lines: list[str] = []

    for line in lines:
        match = email_line_pattern.match(line)
        if not match:
            new_lines.append(line)
            continue

        current_email = match.group("email").strip()
        new_email = replace_email_with_template(
            search_template=search_template,
            replace_template=replace_template,
            email=current_email,
        )

        if new_email:
            prefix = match.group(1)
            new_lines.append(f"{prefix}{new_email}")
            replaced_count += 1
        else:
            new_lines.append(line)

    newline = "\r\n" if "\r\n" in vcard_text else "\n"
    return newline.join(new_lines), replaced_count


def _sanitize_filename_component(value: str) -> str:
    """Return filename-safe component; fallback to 'user' if empty."""
    if not value:
        return "user"
    sanitized = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    sanitized = sanitized.strip("._")
    return sanitized or "user"


def _delete_contact_vcard(
    settings: "SettingParams",
    session: requests.Session,
    contact_url: str,
    etag: str | None = None,
    user_email: str | None = None,
) -> int:
    """DELETE contact from CardDAV; returns deleted_contacts."""
    try:
        if settings.dry_run:
            logger.info(
                f"[{user_email}] Dry run: would delete contact {contact_url} for user {user_email}"
            )
            return 1

        headers = {}
        if etag:
            headers["If-Match"] = etag

        logger.debug(
            f"Deleting contact {contact_url} for user {user_email}, Method: DELETE"
        )
        logger.debug(f"Headers: {headers}")

        retries = 1
        while True:
            response = session.delete(contact_url, headers=headers, timeout=30)
            logger.debug(f"Response: {response.status_code} {response.text}")
            if response.status_code not in (200, 204):
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Failed to delete contact {contact_url}: {response.status_code} {response.text}")
                    return 0
            else:
                return 1

    except requests.RequestException as exc:
        logger.error(f"Failed to delete contact {contact_url}: {exc}")
        return 0


def _update_contact_vcard(
    settings: "SettingParams",
    session: requests.Session,
    contact_url: str,
    updated_vcard: str,
    etag: str | None = None,
    user_email: str | None = None,
) -> int:
    """PUT updated vCard back to CardDAV, respecting dry_run and ETag."""
    try:
        if settings.dry_run:
            logger.info(
                f"[{user_email}] Dry run: update contact {contact_url} with new vCard for user {user_email}"
            )
            return 1

        headers = {"Content-Type": "text/vcard; charset=utf-8"}
        if etag:
            headers["If-Match"] = etag

        logger.debug(f"Updated vCard: {updated_vcard}")
        logger.debug(
            f"Updating contact {contact_url} for user {user_email}, Method: PUT"
        )
        logger.debug(f"Data: {updated_vcard.encode('utf-8')}")
        logger.debug(f"Headers: {headers}")

        retries = 1
        while True:
            response = session.put(
            contact_url,
            data=updated_vcard.encode("utf-8"),
            headers=headers,
            timeout=30,
            )
            logger.debug(f"Response: {response.status_code} {response.text}")
            if response.status_code not in (200, 204):
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Failed to update contact {contact_url}: {response.status_code} {response.text}")
                    return 0
            else:
                return 1

    except requests.RequestException as exc:
        logger.error(f"Failed to update contact {contact_url}: {exc}")
        return 0


def delete_contacts_in_addressbook(settings: "SettingParams", addressbook_url: str, session: requests.Session) -> int:
    """Delete all contacts within a specific addressbook."""
    deleted = 0
    for href in _list_vcard_hrefs(addressbook_url, session):
        contact_url = urljoin(addressbook_url, href)
        try:
            if settings.dry_run:
                logger.info(f"Dry run: would delete contact {contact_url}")
                deleted += 1
                continue
            logger.debug(f"Deleting contact {contact_url}, Method: DELETE")
            retries = 1
            while True:
                response = session.delete(contact_url, timeout=30)
                logger.debug(f"Response: {response.status_code} {response.text}")
                if response.status_code not in (200, 204):
                    if retries < MAX_RETRIES:
                        logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                        time.sleep(RETRIES_DELAY_SEC * retries)
                        retries += 1
                    else:
                        logger.error(f"Failed to delete contact {contact_url}: {response.status_code} {response.text}")
                        continue
                else:
                    deleted += 1
                    break

        except requests.RequestException as exc:
            logger.error(f"Failed to delete contact {contact_url}: {exc}")
            continue

    return deleted


def delete_all_contacts_for_user(settings: "SettingParams", email: str) -> int:
    """Delete all personal contacts for a single user. Returns number deleted."""
    token = get_service_app_token(settings, email)

    session = requests.Session()
    session.auth = HTTPBasicAuth(email, token)

    addressbook_home_url = f"{CARDDAV_BASE_URL.rstrip('/')}/{email}/"
    addressbooks = discover_addressbooks(addressbook_home_url, session)
    if not addressbooks:
        logger.warning(f"No addressbooks found for {email}")
        return 0

    total_deleted = 0
    for book in addressbooks:
        # Удаляем только личные контакты
        if book['name'] == 'Personal':
            logger.info(f"[{email}] Deleting contacts from '{book['name']}'")
            deleted = delete_contacts_in_addressbook(settings, book["url"], session)
            total_deleted += deleted
            logger.info(f"[{email}] Deleted {deleted} contacts from '{book['name']}'")
    return total_deleted


def export_contacts_for_user(settings: "SettingParams", user: dict) -> int:
    """
    Экспортирует все контакты пользователя в один VCF файл.
    Возвращает количество экспортированных контактов.
    """
    user_email = user.get("email") if isinstance(user, dict) else None
    user_alias = user.get("nickname") if isinstance(user, dict) else None

    if not user_email:
        logger.warning(f"Skipping user without email key: {user}")
        return 0

    token = get_service_app_token(settings, user_email)

    session = requests.Session()
    session.auth = HTTPBasicAuth(user_email, token)

    addressbook_home_url = f"{CARDDAV_BASE_URL.rstrip('/')}/{user_email}/"
    addressbooks = discover_addressbooks(addressbook_home_url, session)
    if not addressbooks:
        logger.warning(f"No addressbooks found for {user_email}")
        return 0

    contacts_data: list[str] = []
    for book in addressbooks:
        if book["name"] != "Personal":
            continue

        vcard_hrefs = list(_list_vcard_hrefs(book["url"], session))
        if not vcard_hrefs:
            continue

        vcards = _fetch_vcards_with_data(book["url"], vcard_hrefs, session)
        for vcard in vcards:
            vcard_body = vcard.get("data")
            if vcard_body and vcard_body.strip():
                contacts_data.append(vcard_body.strip())

    if not contacts_data:
        logger.info(f"[{user_email}] Контактов не найдено, экспорт пропущен.")
        return 0

    try:
        os.makedirs(settings.vcard_folder, exist_ok=True)
    except OSError as exc:
        logger.error(f"[{user_email}] Не удалось создать каталог '{settings.vcard_folder}': {exc}")
        return 0

    timestamp = datetime.now().strftime("%y%m%d_%H%M%S")
    alias_safe = _sanitize_filename_component(user_alias or user_email.split("@")[0])
    file_name = f"{alias_safe}_{timestamp}.vcf"
    file_path = os.path.join(settings.vcard_folder, file_name)

    file_content = "\n\n".join(contacts_data)
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(file_content)
            if not file_content.endswith("\n"):
                f.write("\n")
    except OSError as exc:
        logger.error(f"[{user_email}] Не удалось записать файл '{file_path}': {exc}")
        return 0

    logger.info(f"[{user_email}] Экспортировано {len(contacts_data)} контактов в {file_path}")
    return len(contacts_data)


def delete_contacts_by_email_patterns(
    settings: "SettingParams",
    users: Iterable[dict],
    target_email_patterns: Iterable[str],
) -> int:
    """
    Remove EMAIL entries from contacts for provided users if they match target
    templates. Returns total number of updated contacts across all users.
    """
    target_templates = [
        email_pattern.strip()
        for email_pattern in target_email_patterns
        if email_pattern and email_pattern.strip()
    ]
    if not target_templates:
        logger.info("No target emails provided for deletion.")
        return 0

    if not users:
        logger.info("No users provided for deletion by email patterns.")
        return 0

    total_updated_contacts = 0
    total_removed_contacts = 0

    for user in users:
        user_email = user.get("email") if isinstance(user, dict) else None
        if not user_email:
            logger.warning(f"Skipping user without email key: {user}")
            continue

        token = get_service_app_token(settings, user_email)

        session = requests.Session()
        session.auth = HTTPBasicAuth(user_email, token)

        addressbook_home_url = f"{CARDDAV_BASE_URL.rstrip('/')}/{user_email}/"
        addressbooks = discover_addressbooks(addressbook_home_url, session)
        if not addressbooks:
            logger.warning(f"No addressbooks found for {user_email}")
            continue

        updated_for_user = 0
        removed_for_user = 0
        for book in addressbooks:
            if book["name"] != "Personal":
                continue

            vcard_hrefs = list(_list_vcard_hrefs(book["url"], session))
            if not vcard_hrefs:
                continue

            vcards = _fetch_vcards_with_data(book["url"], vcard_hrefs, session)
            for vcard in vcards:
                emails_in_card = _extract_emails_from_vcard_text(vcard["data"])
                if not emails_in_card:
                    continue

                emails_to_remove = {
                    email
                    for email in emails_in_card
                    if any(
                        match_email_with_template(template, email)
                        for template in target_templates
                    )
                }
                if not emails_to_remove:
                    continue

                updated_vcard = _remove_emails_from_vcard(
                    vcard["data"], emails_to_remove
                )
                if updated_vcard == vcard["data"]:
                    logger.debug(
                        f"[{user_email}] Skip contact {vcard.get('url')}: nothing to update."
                    )
                    continue

                contact_url = vcard["url"]
                etag = vcard.get("etag")
                updated_count = 0
                removed_count = 0
                if len(emails_to_remove) == len(emails_in_card):
                    removed_count = _delete_contact_vcard(
                        settings=settings,
                        session=session,
                        contact_url=contact_url,
                        etag=etag,
                        user_email=user_email,
                    )
                else:
                    updated_count = _update_contact_vcard(
                        settings=settings,
                        session=session,
                        contact_url=contact_url,
                        updated_vcard=updated_vcard,
                        etag=etag,
                        user_email=user_email,
                    )

                updated_for_user += updated_count
                removed_for_user += removed_count

        logger.info(
            f"[{user_email}] Updated {updated_for_user} contacts; removed "
            f"{removed_for_user} contacts."
        )
        total_updated_contacts += updated_for_user
        total_removed_contacts += removed_for_user

    logger.info(
        f"Total updated contacts across users: {total_updated_contacts}. "
        f"Total contacts removed: {total_removed_contacts}"
    )
    return total_updated_contacts


def update_contacts_email_by_template(
    settings: "SettingParams",
    users: Iterable[dict],
    search_template: str,
    replace_template: str,
) -> int:
    """
    Обновляет EMAIL в контактах пользователей по заданному шаблону.
    Возвращает количество обновленных контактов.
    """
    search_template = search_template.strip()
    replace_template = replace_template.strip()

    if not search_template or not replace_template:
        logger.info("Templates for search/replace are empty. Nothing to do.")
        return 0

    if not users:
        logger.info("No users provided for email replacement.")
        return 0

    total_updated_contacts = 0
    total_replaced_emails = 0

    for user in users:
        user_email = user.get("email") if isinstance(user, dict) else None
        if not user_email:
            logger.warning(f"Skipping user without email key: {user}")
            continue

        token = get_service_app_token(settings, user_email)

        session = requests.Session()
        session.auth = HTTPBasicAuth(user_email, token)

        addressbook_home_url = f"{CARDDAV_BASE_URL.rstrip('/')}/{user_email}/"
        addressbooks = discover_addressbooks(addressbook_home_url, session)
        if not addressbooks:
            logger.warning(f"No addressbooks found for {user_email}")
            continue

        updated_for_user = 0
        replaced_for_user = 0
        for book in addressbooks:
            if book["name"] != "Personal":
                continue

            vcard_hrefs = list(_list_vcard_hrefs(book["url"], session))
            if not vcard_hrefs:
                continue

            vcards = _fetch_vcards_with_data(book["url"], vcard_hrefs, session)
            for vcard in vcards:
                updated_vcard, replaced_count = _replace_emails_in_vcard(
                    vcard["data"], search_template, replace_template
                )
                if replaced_count <= 0:
                    continue

                contact_url = vcard["url"]
                etag = vcard.get("etag")
                updated_count = _update_contact_vcard(
                    settings=settings,
                    session=session,
                    contact_url=contact_url,
                    updated_vcard=updated_vcard,
                    etag=etag,
                    user_email=user_email,
                )

                if updated_count:
                    updated_for_user += updated_count
                    replaced_for_user += replaced_count

        logger.info(
            f"[{user_email}] Updated {updated_for_user} contacts; "
            f"replaced {replaced_for_user} email entries."
        )
        total_updated_contacts += updated_for_user
        total_replaced_emails += replaced_for_user

    logger.info(
        f"Total updated contacts across users: {total_updated_contacts}. "
        f"Total email entries replaced: {total_replaced_emails}"
    )
    return total_updated_contacts


def delete_contacts_for_users(settings: "SettingParams") -> int:

    try:
        users = read_users_csv(settings.users_file)
    except Exception as exc:
        logger.error(exc)
        return 1

    if not users:
        logger.error("Файл пользователей пуст или не содержит столбец Email.")
        return 1

    if settings.dry_run:
        logger.info("Dry run включен: контакты удаляться не будут, показываем только список.")

    total_processed = 0
    for user in users:
        email = user.get("Email")
        if not email:
            continue
        try:
            deleted = delete_all_contacts_for_user(settings, email)
            logger.info(f"[{email}] Всего удалено: {deleted}")
            total_processed += 1
        except TokenError as exc:
            logger.error(f"[{email}] Ошибка получения токена: {exc}")
        except Exception as exc:  # catch-all to continue processing other users
            logger.error(f"[{email}] Не удалось удалить контакты: {exc}")

    logger.info(f"Обработано пользователей: {total_processed}")


def download_users_attrib_to_file(settings: "SettingParams", users: list = None):
    """
    Выгружает данные пользователей из API 360 в два файла:
    1. Файл с полным списком атрибутов пользователя, как возвращает API (settings.all_users_file)
    2. Файл с полями, аналогичными полям для создания пользователей (settings.all_users_file + '_short.csv')
    Также добавляет функцию проверки уникальности алиасов.
    """
    if not users:
        users = get_all_api360_users(settings, force=True)
    if not users:
        logger.error("Не найдено пользователей из API 360. Проверьте ваши настройки.")
        return

    # --- 1. Выгрузка полного списка атрибутов пользователя ---
    with open(settings.all_users_file, 'w', encoding='utf-8', newline='') as csv_file:

        fieldnames = list(users[0].keys())
        # Исключаем ключ full_groups из fieldnames
        if "full_groups" in fieldnames:
            fieldnames.remove("full_groups")
        if "isEnabledUpdatedAt" not in fieldnames:
            fieldnames.append("isEnabledUpdatedAt")
        writer = csv.DictWriter(csv_file, delimiter=';', fieldnames=fieldnames)
        writer.writeheader()
        for user in users:
            # Создаем копию словаря без ключа full_groups
            user_copy = {k: v for k, v in user.items() if k != 'full_groups'}
            writer.writerow(user_copy)
        logger.info(f"Сохранено {len(users)} пользователей в файл {settings.all_users_file}")

def get_all_api360_users(settings: "SettingParams", force = False):
    if not force:
        logger.info("Getting all users of the organisation from cache...")

    if not settings.all_users or force or (datetime.now() - settings.all_users_get_timestamp).total_seconds() > ALL_USERS_REFRESH_IN_MINUTES * 60:
        logger.info("Getting all users of the organisation from API...")
        settings.all_users = get_all_api360_users_from_api(settings)
        settings.all_users_get_timestamp = datetime.now()
    return settings.all_users

def get_all_api360_users_from_api(settings: "SettingParams"):
    logger.info("Получение всех пользователей организации из API...")
    url = f'{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/users'
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    has_errors = False
    users = []
    current_page = 1
    last_page = 1
    while current_page <= last_page:
        params = {'page': current_page, 'perPage': USERS_PER_PAGE_FROM_API}
        try:
            retries = 1
            while True:
                logger.debug(f"GET URL - {url}")
                response = requests.get(url, headers=headers, params=params)
                logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
                if response.status_code != HTTPStatus.OK.value:
                    logger.error(f"!!! ОШИБКА !!! при GET запросе url - {url}: {response.status_code}. Сообщение об ошибке: {response.text}")
                    if retries < MAX_RETRIES:
                        logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                        time.sleep(RETRIES_DELAY_SEC * retries)
                        retries += 1
                    else:
                        has_errors = True
                        break
                else:
                    for user in response.json()['users']:
                        if not user.get('isRobot') and int(user["id"]) >= 1130000000000000:
                            users.append(user)
                    logger.debug(f"Загружено {len(response.json()['users'])} пользователей. Текущая страница - {current_page} (всего {last_page} страниц).")
                    current_page += 1
                    last_page = response.json()['pages']
                    break

        except requests.exceptions.RequestException as e:
            logger.error(f"!!! ERROR !!! {type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
            has_errors = True
            break

        if has_errors:
            break

    if has_errors:
        print("Есть ошибки при GET запросах. Возвращается пустой список пользователей.")
        return []
    
    return users

def remove_contacts_for_users_prompt(settings: "SettingParams", use_file = True):
    """
    Запрашивает у пользователя шаблоны email для удаления email из контактов.
    Возвращает список шаблонов email и список пользователей.
    """

    break_flag = False
    all_users_flag = False

    if use_file:
        source_emails = read_users_csv(settings.users_file)
        if not source_emails:
            logger.info(f"No emails found in file {settings.users_file}. Try again.")
            return
        users_to_add, break_flag, double_users_flag, all_users_flag = find_users_prompt(settings, answer = ",".join(source_emails))
        logger.info(f"Found {len(users_to_add)} users to update emails for.")
        logger.info("\n")
        if not users_to_add:
            logger.info("No users found in Y360 organization to match with source emails. Try again.")
            return

    while True:

        if not use_file:
            while True:
                users_to_add = []
                double_users_flag = False
                users_to_add, break_flag, double_users_flag, all_users_flag = find_users_prompt(settings)

                if break_flag:
                    break
                
                if double_users_flag:
                    continue

                if not users_to_add:
                    logger.info("No users to add. Try again.")
                    continue

                logger.info(f"Found {len(users_to_add)} users to delete emails from.")
                logger.info("\n")
                break

            if break_flag:
                break

        if not users_to_add:
            logger.info("No users to add. Try again.")
            return

        answer = input(
            f"Confirm removal of all contacts for {len(users_to_add)} users? (y/n): "
        )
        if answer.strip() == "y":

            if settings.dry_run:
                logger.info("Dry run включен: контакты удаляться не будут, показываем только список.")

            total_processed = 0
            for user in users_to_add:
                email = user.get("email")
                if not email:
                    continue
                try:
                    deleted = delete_all_contacts_for_user(settings, email)
                    logger.info(f"[{email}] Всего удалено: {deleted}")
                    total_processed += 1
                except TokenError as exc:
                    logger.error(f"[{email}] Ошибка получения токена: {exc}")
                except Exception as exc:  # catch-all to continue processing other users
                    logger.error(f"[{email}] Не удалось удалить контакты: {exc}")

            logger.info(f"Обработано пользователей: {total_processed}")
            logger.info("Press Enter to continue...")
            input() # wait for user to press Enter
            return
        else:
            logger.info("Operation cancelled by user.")
            logger.info("Press Enter to continue...")
            input()
            return

def remove_contacts_by_email_patterns_prompt(settings: "SettingParams", use_file = True):
    """
    Запрашивает у пользователя шаблоны email для удаления email из контактов.
    Возвращает список шаблонов email и список пользователей.
    """

    break_flag = False
    all_users_flag = False

    if use_file:
        source_emails = read_users_csv(settings.users_file)
        if not source_emails:
            logger.info(f"No emails found in file {settings.users_file}. Try again.")
            return
        users_to_add, break_flag, double_users_flag, all_users_flag = find_users_prompt(settings, answer = ",".join(source_emails))
        logger.info(f"Found {len(users_to_add)} users to update emails for.")
        logger.info("\n")
        if not users_to_add:
            logger.info("No users found in Y360 organization to match with source emails. Try again.")
            return

    while True:

        if not use_file:
            while True:
                users_to_add = []
                double_users_flag = False
                users_to_add, break_flag, double_users_flag, all_users_flag = find_users_prompt(settings)

                if break_flag:
                    break
                
                if double_users_flag:
                    continue

                if not users_to_add:
                    logger.info("No users to add. Try again.")
                    continue

                logger.info(f"Found {len(users_to_add)} users to delete emails from.")
                logger.info("\n")
                break

            if break_flag:
                break

        if not users_to_add:
            logger.info("No users to add. Try again.")
            return

        while True:
            target_templates = []
            answer = input(
                "Enter email templates to delete, separated by space, comma or semicolon or press Enter to cancel: "
            )
            if not answer.strip():
                break_flag = True
                break

            pattern = r'[;,\s]+'
            templates = re.split(pattern, answer)
            if not isinstance(templates, list):
                templates = [templates]
            for template in templates:
                template = template.strip()
                if not template:
                    continue
                # Basic validation - template should not be empty and should contain valid characters
                if not re.match(r'^[\w\.\-\*@]+$', template):
                    logger.error(f"Template '{template}' contains invalid characters. Only letters, numbers, dots, hyphens, @ and * are allowed. Try again.")
                    logger.info("\n")
                    continue
                else:
                    target_templates.append(template)
            if not target_templates:
                logger.error("No templates to delete. Try again.")
                logger.info("\n")
                continue
            else:
                break

        if break_flag:
            break

        answer = input(
            f"Confirm removal of matching email entries from contacts of {len(users_to_add)} users? (y/n): "
        )
        if answer.strip() == "y":
            delete_contacts_by_email_patterns(settings, users_to_add, target_templates)
            logger.info("Email entries removed successfully.")
            logger.info("Press Enter to continue...")
            input()
            return
        else:
            logger.info("Operation cancelled by user.")
            logger.info("Press Enter to continue...")
            input()
            return


def change_emails_in_contacts_prompt(settings: "SettingParams", use_file = True):
    """
    Запрашивает пользователей и шаблоны для замены email в контактах.
    """
    break_flag = False
    if use_file:
        source_emails = read_users_csv(settings.users_file)
        if not source_emails:
            logger.info(f"No emails found in file {settings.users_file}. Try again.")
            return
        users_to_add, break_flag, double_users_flag, all_users_flag = find_users_prompt(settings, answer = ",".join(source_emails))
        logger.info(f"Found {len(users_to_add)} users to update emails for.")
        logger.info("\n")
        if not users_to_add:
            logger.info("No users found in Y360 organization to match with source emails. Try again.")
            return

    while True:
        if not use_file:
            while True:
                users_to_add = []
                double_users_flag = False
                users_to_add, break_flag, double_users_flag, all_users_flag = find_users_prompt(settings)

                if break_flag:
                    break

                if double_users_flag:
                    continue

                if not users_to_add:
                    logger.info("No users to add. Try again.")
                    continue

                logger.info(f"Found {len(users_to_add)} users to update emails for.")
                logger.info("\n")
                break

            if break_flag:
                break

        if not users_to_add:
            logger.info("No users to add. Try again.")
            return

        while True:
            answer = input(
                "Введите через пробел два выражения: шаблон для поиска и шаблон замены (Enter - отмена): "
            )
            if not answer.strip():
                break_flag = True
                break

            parts = answer.strip().split()
            if len(parts) != 2:
                logger.error("Нужно указать два значения через пробел. Повторите ввод.")
                logger.info("\n")
                continue

            search_template, replace_template = parts
            for template_value, label in (
                (search_template, "шаблон поиска"),
                (replace_template, "шаблон замены"),
            ):
                if not re.match(r'^[\w\.\-\*@]+$', template_value):
                    logger.error(
                        f"{label.title()} '{template_value}' содержит недопустимые символы. "
                        "Разрешены буквы, цифры, точка, дефис, @ и *."
                    )
                    logger.info("\n")
                    break
            else:
                break

        if break_flag:
            break

        answer = input(
            f"Подтвердите замену email по шаблону '{search_template}' -> '{replace_template}' "
            f"для {len(users_to_add)} пользователей? (y/n): "
        )
        if answer.strip().lower() == "y":
            update_contacts_email_by_template(
                settings, users_to_add, search_template, replace_template
            )
            logger.info("Email адреса обновлены.")
            logger.info("Press Enter to continue...")
            input()
            return
        else:
            logger.info("Operation cancelled by user.")
            logger.info("Press Enter to continue...")
            input()
            return

def export_contacts_for_users_prompt(settings: "SettingParams", use_file: bool = True):
    """
    Запрашивает список пользователей и сохраняет их контакты в VCF файлы.
    """
    break_flag = False

    if use_file:
        source_emails = read_users_csv(settings.users_file)
        if not source_emails:
            logger.info(f"No emails found in file {settings.users_file}. Try again.")
            return
        users_to_add, break_flag, double_users_flag, all_users_flag = find_users_prompt(settings, answer=",".join(source_emails))
        logger.info(f"Found {len(users_to_add)} users to export contacts for.")
        logger.info("\n")
        if not users_to_add:
            logger.info("No users found in Y360 organization to match with source emails. Try again.")
            return

    while True:
        if not use_file:
            while True:
                users_to_add = []
                double_users_flag = False
                users_to_add, break_flag, double_users_flag, all_users_flag = find_users_prompt(settings)

                if break_flag:
                    break

                if double_users_flag:
                    continue

                if not users_to_add:
                    logger.info("No users to add. Try again.")
                    continue

                logger.info(f"Found {len(users_to_add)} users to export contacts for.")
                logger.info("\n")
                break

            if break_flag:
                break

        if not users_to_add:
            logger.info("No users to add. Try again.")
            return

        answer = input(
            f"Сохранить контакты для {len(users_to_add)} пользователей в каталог '{settings.vcard_folder}'? (y/n): "
        )
        if answer.strip().lower() == "y":
            total_files = 0
            total_contacts = 0
            for user in users_to_add:
                exported = export_contacts_for_user(settings, user)
                if exported > 0:
                    total_files += 1
                    total_contacts += exported
            logger.info(
                f"Экспорт завершен. Создано файлов: {total_files}. "
                f"Всего контактов выгружено: {total_contacts}"
            )
            logger.info("Press Enter to continue...")
            input()
            return
        else:
            logger.info("Operation cancelled by user.")
            logger.info("Press Enter to continue...")
            input()
            return


def  find_users_prompt(settings: "SettingParams", answer = "") -> tuple[list[dict], bool, bool, bool]:
    break_flag = False
    double_users_flag = False
    users_to_add = []
    all_users_flag = False
    if not answer:
        answer = input(
            "Enter users aliases or uid or last name, separated by comma or space (* - all users, ! - load users from file): "
        )

    if not answer.strip():
        break_flag = True
    else:
        users = get_all_api360_users(settings)
        if not users:
            logger.info("No users found in Y360 organization.")
            break_flag = True

        if answer.strip() == "*":
            all_users_flag = True
            return users, break_flag, double_users_flag, all_users_flag

        search_users = []
        if answer.strip() == "!":
            search_users = read_users_csv(settings.users_file)
            if not search_users:
                logger.info("No users found in file {settings.users_file}.")
                break_flag = True
                return users_to_add, break_flag, double_users_flag, all_users_flag

        if not search_users:
            pattern = r'[;,\s]+'
            search_users = re.split(pattern, answer)
        
        #rus_pattern = re.compile('[-А-Яа-яЁё]+')
        #anti_rus_pattern = r'[^\u0400-\u04FF\s]'

        for searched in search_users:
            if "@" in searched.strip():
                searched = searched.split("@")[0]
            found_flag = False
            if all(char.isdigit() for char in searched.strip()):
                if len(searched.strip()) == 16 and searched.strip().startswith("113"):
                    for user in users:
                        if user['id'] == searched.strip():
                            logger.debug(f"User found: {user['nickname']} ({user['id']})")
                            users_to_add.append(user)
                            found_flag = True
                            break

            else:
                found_last_name_user = []
                for user in users:
                    aliases_lower_case = [r.lower() for r in user['aliases']]
                    if user['nickname'].lower() == searched.lower().strip() or searched.lower().strip() in aliases_lower_case:
                        logger.debug(f"User found: {user['nickname']} ({user['id']})")
                        users_to_add.append(user)
                        found_flag = True
                        break
                    if user['name']['last'].lower() == searched.lower().strip():
                        found_last_name_user.append(user)
                if not found_flag and found_last_name_user:
                    if len(found_last_name_user) == 1:
                        logger.debug(f"User found ({searched}): {found_last_name_user[0]['nickname']} ({found_last_name_user[0]['id']}, {found_last_name_user[0]['position']})")
                        users_to_add.append(found_last_name_user[0])
                        found_flag = True
                    else:
                        logger.error(f"User {searched} found more than one user:")
                        for user in found_last_name_user:
                            logger.error(f" - last name {user['name']['last']}, nickname {user['nickname']} ({user['id']}, {user['position']})")
                        logger.error("Refine your search parameters.")
                        double_users_flag = True
                        break

            if not found_flag:
                logger.error(f"User {searched} not found in Y360 organization.")

    return users_to_add, break_flag, double_users_flag, all_users_flag


def get_address_book_collect_status(settings: "SettingParams", user_id: str) -> bool | None:
    """
    Fetch automatic contacts collection status for a user via API 360.
    Returns True/False on success, or None on failure.
    """
    url = f"{DEFAULT_360_API_URL}/admin/v1/org/{settings.org_id}/mail/users/{user_id}/settings/address_book"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}

    try:
        retries = 1
        while True:
            logger.debug(f"GET url - {url}")
            response = requests.get(url, headers=headers)
            logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")

            if response.status_code != HTTPStatus.OK.value:
                logger.error(
                    f"Error during GET request for user {user_id}: "
                    f"{response.status_code}. Error message: {response.text}"
                )
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(
                        f"Error. Unable to fetch collectAddresses status for user {user_id}."
                    )
                    return None
            else:
                payload = response.json() if response.content else {}
                collect_value = payload.get("collectAddresses")
                if isinstance(collect_value, bool):
                    return collect_value
                logger.error(
                    f"collectAddresses is missing or not boolean for user {user_id}: {payload}"
                )
                return None
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return None


def export_collect_status_for_users(settings: "SettingParams", users: list[dict]) -> str | None:
    """
    Export automatic contacts collection status for provided users to a CSV file.
    """
    if not users:
        logger.info("No users provided for export.")
        return None

    base_name = settings.contacts_collect_file or "collect_status"
    timestamp = datetime.now().strftime("%y%m%d_%H%M%S")
    base_dir = os.path.dirname(base_name)
    base_stem = os.path.basename(base_name)
    file_name = f"{base_stem}_{timestamp}.csv"
    file_path = os.path.join(base_dir, file_name) if base_dir else file_name

    if base_dir:
        try:
            os.makedirs(base_dir, exist_ok=True)
        except OSError as exc:
            logger.error(f"Failed to create directory '{base_dir}': {exc}")
            return None

    rows_written = 0
    try:
        with open(file_path, "w", encoding="utf-8", newline="") as csv_file:
            fieldnames = ["email", "collectAddresses"]
            writer = csv.DictWriter(csv_file, delimiter=';', fieldnames=fieldnames)
            writer.writeheader()

            for user in users:
                user_email = user.get("email")
                user_id = user.get("id")
                if not user_email or not user_id:
                    logger.warning(f"Skipping user without required fields: {user}")
                    continue

                collect_status = get_address_book_collect_status(settings, user_id)
                if collect_status is None:
                    continue

                writer.writerow(
                    {
                        "email": user_email,
                        "collectAddresses": collect_status,
                    }
                )
                rows_written += 1
    except OSError as exc:
        logger.error(f"Failed to write file '{file_path}': {exc}")
        return None

    if rows_written == 0:
        logger.info("No statuses were written to file.")
        return None

    logger.info(
        f"Saved collectAddresses status for {rows_written} users to {file_path}"
    )
    return file_path


def export_collect_status_for_users_prompt(settings: "SettingParams"):
    """
    Ask for users list and export automatic contacts collection status to CSV.
    """
    while True:
        users_to_process, break_flag, double_users_flag, _all_users_flag = find_users_prompt(settings)
        if break_flag:
            break

        if double_users_flag:
            continue

        if not users_to_process:
            logger.info("No users to export. Try again.")
            continue

        file_path = export_collect_status_for_users(settings, users_to_process)
        if file_path:
            logger.info("Export completed successfully.")
        else:
            logger.info("Export finished without creating file.")

        logger.info("Press Enter to continue...")
        input()
        break

def set_address_book_collect(settings: "SettingParams", user_id: str, collect: bool) -> bool:
    """
    Toggle automatic personal contacts collection for a user via API 360.
    """
    url = f"{DEFAULT_360_API_URL}/admin/v1/org/{settings.org_id}/mail/users/{user_id}/settings/address_book"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    payload = {"collectAddresses": collect}

    try:
        retries = 1
        while True:
            logger.debug(f"POST url - {url}")
            logger.debug(f"POST payload - {payload}")
            if settings.dry_run:
                logger.info(
                    f"Dry run: Would set collectAddresses={collect} for user {user_id}"
                )
                return True

            response = requests.post(url, headers=headers, json=payload)
            logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")

            if response.status_code != HTTPStatus.OK.value:
                logger.error(
                    f"Error during POST request for user {user_id}: "
                    f"{response.status_code}. Error message: {response.text}"
                )
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(
                        f"Error. Setting collectAddresses={collect} for user {user_id} failed."
                    )
                    return False
            else:
                logger.info(
                    f"Success - collectAddresses set to {collect} for user {user_id}"
                )
                return True
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return False


def change_personal_contacts_collect_prompt(settings: "SettingParams", collect: bool):
    """
    Ask for users list and change automatic personal contacts collection for each.
    """
    if collect:
        action = "enable"
    else:
        action = "disable"

    while True:
        users_to_update, break_flag, double_users_flag, _all_users_flag = find_users_prompt(settings)
        if break_flag:
            break

        if double_users_flag:
            continue

        if not users_to_update:
            logger.info("No users to update. Exiting.")
            continue

        if len(users_to_update) == 1:
            ask_msg = (
                f"Change auto-collect contacts to {action} for "
                f"{users_to_update[0]['id']} ({users_to_update[0]['nickname']})? (y/n): "
            )
        else:
            ask_msg = (
                f"Change auto-collect contacts to {action} for "
                f"{len(users_to_update)} users? (y/n): "
            )

        if not input(ask_msg) == "y":
            logger.info("Operation cancelled by user.")
            logger.info("Press Enter to continue...")
            input()
            continue

        success = 0
        for user in users_to_update:
            if set_address_book_collect(settings, user['id'], collect):
                success += 1

        logger.info(f"Changed auto-collect to {action} for {success} of {len(users_to_update)} users.")
        logger.info("Press Enter to continue...")
        input()
        break

def match_email_with_template(template: str, email: str) -> bool:
    """
    Проверяет, соответствует ли email адрес заданному шаблону с поддержкой wildcard символов *.

    Args:
        template (str): Шаблон для поиска (domain.com или alias@domain.com с возможными *)
        email (str): Email адрес для проверки

    Returns:
        bool: True если email соответствует шаблону, False в противном случае

    Examples:
        *@domain.com - все адреса в домене domain.com
        *.domain.com - все адреса в любом домене третьего уровня в домене domain.com
        andy@* - все адреса с алисом andy в любом домене
    """
    if not template or not email:
        return False

    template = template.lower().strip()
    email = email.lower().strip()

    # Разбиваем email на локальную часть и домен
    if '@' not in email:
        return False
    email_local, email_domain = email.split('@', 1)

    # Проверяем формат шаблона
    if '@' in template:
        # Шаблон в формате alias@domain
        if template.count('@') != 1:
            return False
        template_local, template_domain = template.split('@', 1)

        # Сравниваем локальные части с wildcard поддержкой
        if not match_with_wildcard(template_local, email_local):
            return False

        # Сравниваем домены с wildcard поддержкой
        if not match_with_wildcard(template_domain, email_domain):
            return False

    else:
        # Шаблон в формате только домен
        if not match_with_wildcard(template, email_domain):
            return False

    return True

def match_with_wildcard(pattern: str, text: str) -> bool:
    """
    Сравнивает текст с шаблоном, поддерживающим wildcard символ *.

    Args:
        pattern (str): Шаблон с возможными *
        text (str): Текст для сравнения

    Returns:
        bool: True если текст соответствует шаблону
    """
    if not pattern or not text:
        return False

    # Экранируем специальные символы regex, кроме *
    escaped = re.escape(pattern)
    # Заменяем экранированные * на .*
    wildcard_pattern = escaped.replace(r'\*', '.*')

    # Добавляем якоря начала и конца строки
    regex_pattern = f'^{wildcard_pattern}$'

    try:
        return bool(re.match(regex_pattern, text, re.IGNORECASE))
    except re.error:
        # Если regex невалиден, возвращаем False
        return False


def replace_email_with_template(
    search_template: str, replace_template: str, email: str
) -> str | None:
    """
    Заменяет email согласно заданным шаблонам. Поддерживает wildcard *.
    Возвращает новый email или None, если замены не требуется.
    """
    if not search_template or not replace_template or not email:
        return None

    search_template = search_template.strip().lower()
    replace_template = replace_template.strip().lower()
    email_original = email.strip()
    email_lower = email_original.lower()

    if not match_email_with_template(search_template, email_lower):
        return None

    if "@" not in email_lower:
        return None
    email_local, email_domain = email_lower.split("@", 1)

    # Строим regex с группами из шаблона поиска
    escaped = re.escape(search_template)
    search_regex = f"^{escaped.replace(r'\\*', '(.+?)')}$"
    captured_groups: list[str] = []
    try:
        search_match = re.match(search_regex, email_lower, re.IGNORECASE)
        if search_match:
            captured_groups = list(search_match.groups())
    except re.error:
        return None

    result_parts: list[str] = []
    before_at = True
    captured_index = 0

    for ch in replace_template:
        if ch == "*":
            if captured_index < len(captured_groups):
                replacement_value = captured_groups[captured_index]
                captured_index += 1
            else:
                replacement_value = email_local if before_at else email_domain
            result_parts.append(replacement_value)
        else:
            if ch == "@":
                before_at = False
            result_parts.append(ch)

    new_email = "".join(result_parts)
    if new_email == email_lower:
        return None
    return new_email


def main_menu(settings: "SettingParams"):

    while True:
        print("\n")
        print("Выберите опцию:")
        print("1. Выгрузить всех пользователей в файл.")
        print("2. Удалить все контакты выбранных пользователей.")
        print("3. Удалить контакты по шаблонам email, для выбранных пользователей.")
        print("4. Изменить email адреса в контактах, для выбранных пользователей.")
        print("5. Сохранить контакты выбранных пользователей в VCF.")
        print("6. Выгрузить в файл информацию об автоматическом сборе контактов для выбранных пользователей.")
        print("7. Включить автоматическое сбора контактов для выбранных пользователей.")
        print("8. Отключить автоматическое сбора контактов для выбранных пользователей.")
        print("0. (Ctrl+C) Выход")
        print("\n")
        choice = input("Введите ваш выбор (0-9): ")

        if choice == "0":
            print("До свидания!")
            break
        elif choice == "1":
            print('\n')
            download_users_attrib_to_file(settings)
        elif choice == "2":
            print('\n')
            remove_contacts_for_users_prompt(settings, use_file = False)
        elif choice == "3":
            print('\n')
            remove_contacts_by_email_patterns_prompt(settings, use_file = False)
        elif choice == "4":
            print('\n')
            change_emails_in_contacts_prompt(settings, use_file = False)
        elif choice == "5":
            print('\n')
            export_contacts_for_users_prompt(settings, use_file = False)
        elif choice == "6":
            print('\n')
            export_collect_status_for_users_prompt(settings)
        elif choice == "7":
            print('\n')
            change_personal_contacts_collect_prompt(settings, collect = True)
        elif choice == "8":
            print('\n')
            change_personal_contacts_collect_prompt(settings, collect = False)
        else:
            logger.error("Неверный выбор. Попробуйте снова.")


if __name__ == "__main__":
    denv_path = os.path.join(os.path.dirname(__file__), '.env')

    if os.path.exists(denv_path):
        load_dotenv(dotenv_path=denv_path,verbose=True, override=True)
    else:
        logger.error("Не найден файл .env. Выход.")
        sys.exit(EXIT_CODE)

    logger.info("\n")
    logger.info("---------------------------------------------------------------------------.")
    logger.info("Запуск скрипта.")
    
    settings = get_settings()
    
    if settings is None:
        logger.error("Проверьте настройки в файле .env и попробуйте снова.")
        sys.exit(EXIT_CODE)
    
    try:
        main_menu(settings)
    except KeyboardInterrupt:
        logger.info("\nCtrl+C pressed. До свидания!")
        sys.exit(EXIT_CODE)
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno}: {e}")
        sys.exit(EXIT_CODE)
