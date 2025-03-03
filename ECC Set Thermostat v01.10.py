#!/usr/bin/env python3

"""
    This routine will send a message to the specified Ecobee thermostat.

    The core Ecobee routines (pyecobee) come from a library originally written by Sherif Fanous (@sfanous)
    at https://github.com/sfanous/Pyecobee;  it is well documented here along with all of the object
    definitions, and Python getter / setter functions.  

            Written by DK Fowler ... 03-Dec-2021        --- v01.00

    Modified to target one of the test thermostats utilized by the CSE 496 Team 7, Spring 2025.
            Modified by DK Fowler ... 03-Mar2025        --- v01.10


"""

from datetime import datetime
import time
import pytz
import json
import os
import sys
import argparse
import smtplib
from email.message import EmailMessage

from pyecobee import *

import socket

# Define version
eccsetthermostat_version = "01.10"
eccsetthermostat_date = "03-Mar-2025"

# Parse the command line arguments for the filename locations, if present
parser = argparse.ArgumentParser(description='''Epiphany Catholic Church Ecobee Set Thermostat Application.
                                            This routine will send a message to the specified Ecobee thermostat.''',
                                 epilog='''Filename parameters may be specified on the command line at invocation, 
                                        or default values will be used for each.''')
parser.add_argument("-l", "-log", "--log-file-path", dest="log_file_path", default="ECCEcobeeSendMessage.log",
                    help="log filename path")
parser.add_argument("-a", "-auth", "--auth", "--authorize-file-path", dest="authorize_file_path",
                    default="ECCEcobeeWrite_tkn.json", help="authorization tokens (write) JSON filename path")
parser.add_argument("-api", "--api", "--api-file-path", dest="api_file_path", default="ECCEcobeeWrite_API.txt",
                    help="default (write) API key filename path")
parser.add_argument("-m", "--gmail_credentials_file_path", default="ECCEcobee_GMail_Credentials.txt",
                    help="default GMail user/pass credentials filename path")
parser.add_argument("-v", "-ver", "--version", action="store_true",
                    help="display application version information")

args = parser.parse_args()

# If the app version is requested on the command line, print it then exit.
if args.version:
    print(
        F"Ecobee send message application, version {eccsetthermostat_version}, {eccsetthermostat_date}...")
    sys.exit(0)

# Location of the authorization file w/ tokens (with write access)
ECCAuthorize = args.authorize_file_path

# Location of the default API key (with write access) if not otherwise provided
ECCEcobeeAPIkey = args.api_file_path

# Location of the GMail credentials file
ECCEcobee_gmail_credentials = args.gmail_credentials_file_path

# Set the default timeout for socket operations, as these sometimes timeout with the default (5 seconds).
socket.setdefaulttimeout(30)

"""
    The ecobee API is based on extensions to the OAuth 2.0 framework. Authorization for a given API
    call requires several initial steps:
        1)  Defining the new application, done manually by an administrator on the Ecobee portal.
            This results in the issuance of an application key.
        2)  An authorization, providing a scope which defines whether the application "scope" will be
            read, write or both access.  The application key from above is used for the authorization
            request, and if successful, results in a 9-digit PIN in the form 'xxxx-xxxx'
            (used here, though there are other methods provided).
        3)  An app registration, done manually by the administrator on the Ecobee portal.  The admin provides
            the PIN from the authorization request previously.  Subsequent calls to the authorization API
            will not be successful until the validation step is performed.  The PIN has a set duration and
            will expire after a defined timeframe, so this step is time-sensitive.
        4)  Token issuance.  Valid access tokens are required for all further calls to the Ecobee API.
            Access tokens have a specified life, which means they will expire after a set amount of time.
            Requests for token issuance include an authorization token from the authorization step above.
            If the token issuance request is successful, access and refresh tokens are provided which
            have set expiration timeframes.
        5)  Refreshing tokens.  As noted in the previous step, the access tokens used for all further API
            requests expire after a set time.  If a subsequent API request fails due to token expiration,
            a new set of access/refresh tokens must be requested.  A refresh request must include the
            valid (non-expired) refresh token from the previous token issuance.

            The last (valid) set of authorization, access, and refresh tokens are stored by this application
            in a JSON-formatted file.

"""

# Set up logging...change as appropriate based on implementation location and logging level
log_file_path = args.log_file_path
# log_file_path = None  # To direct logging to console instead of file
logging.basicConfig(
    filename=log_file_path,
    level=logging.DEBUG,
    format="%(asctime)s:%(levelname)s: %(name)s: line: %(lineno)d %(message)s"
)
logger = logging.getLogger('set_thermostat')

# Dictionary that contains authorization information used globally
json_auth_dict = {}


def main():
    now = datetime.now()
    date_now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    print(F"*** Initiating Ecobee send message application, {date_now_str} ***")
    logger.info(F"*** Initiating Ecobee send message application, {date_now_str} ***")
    print(F"*** ECC Ecobee send message version {eccsetthermostat_version}, {eccsetthermostat_date} ***")
    logger.info(F"*** ECC Ecobee send message version {eccsetthermostat_version}, {eccsetthermostat_date} ***")

    logger.info(F"Log filename:                       {args.log_file_path}")
    logger.info(F"Authorization token filename:       {args.authorize_file_path}")
    logger.info(F"Default API key filename:           {args.api_file_path}")
    logger.info(F"Gmail credentials filename:         {args.gmail_credentials_file_path}")

    # Attempt to open the credentials / authorization file and read contents
    try:
        with open(ECCAuthorize, "r") as read_auth:
            json_auth_dict = json.load(read_auth)

    # Handle [Errno 2] No such file or directory, JSON decoding error (syntax error in file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(F"Missing or invalid authorization token JSON file...")
        logger.error(F"...error:  {e}")
        print(F"Missing or invalid authorization token JSON file...")
        print(F"...error:  {e}")
        # Typically a missing authorization token file would occur during first-run of app.  Get the default
        # API key.  Further action will be required to authorize the app prior to subsequent runs.
        app_key = get_api()

    except Exception as e:  # handle other errors
        logger.error(F"Error occurred while attempting to initialize Ecobee service object...aborting.")
        logger.error(F"...error was:  {e}")
        print(F"Error occurred while attempting to initialize Ecobee service object...aborting.")
        print(F"...error was:  {e}")
        send_mail_and_exit()

    # If we have read contents from the JSON authorization token file, display the contents
    try:
        logger.debug(F"JSON token data structure:  Keys: {len(json_auth_dict)}")
        logger.debug(F"...elements:  {json_auth_dict}")
        for pelement in json_auth_dict:
            logger.debug(F"...JSON auth contents: {pelement}:  {json_auth_dict.get(pelement)}")
            # print(F"...JSON auth contents: {pelement}:  {json_auth_dict.get(pelement)}")
        app_key = json_auth_dict['application_key']

    except (UnboundLocalError, NameError) as e:  # if not defined or referenced before assignment, then continue
        pass

    # initialize an Ecobee service object
    try:
        ecobee_service = EcobeeService(thermostat_name='',
                                       application_key=app_key,
                                       scope=Scope.SMART_WRITE)
    except KeyError as e:  # handle missing API key
        logger.error(F"Missing or invalid API key while attempting to initialize Ecobee service object.")
        logger.error(F"...Ecobee service return error:  {e}")
        print(F"Missing or invalid API key while attempting to initialize Ecobee service object.")
        print(F"...Ecobee service return error:  {e}")
        send_mail_and_exit()  # Not much point in continuing if we don't have a valid application key

    logger.info(ecobee_service.pretty_format())

    # If we have a value for the authorization code, access and refresh tokens in the stored credentials,
    # assign these to the appropriate fields in the EcobeeService object
    try:
        if 'authorization_token' in json_auth_dict:
            ecobee_service.authorization_token = json_auth_dict['authorization_token']
        if 'access_token' in json_auth_dict:
            ecobee_service.access_token = json_auth_dict['access_token']
        if 'refresh_token' in json_auth_dict:
            ecobee_service.refresh_token = json_auth_dict['refresh_token']
    # If referenced before assignment or not defined, then continue
    except (UnboundLocalError, NameError) as e:
        pass

    # Test for no authorization token present; this would typically happen at first run where no
    # access credentials are stored
    if not ecobee_service.authorization_token:
        logger.info(F"No authorization token found...requesting...")
        authorize(ecobee_service)

    # Test for no access token present; this would typically happen at first run where no access
    # credentials are stored, or where authorization has just occurred
    if not ecobee_service.access_token:
        logger.info(F"No access token found...requesting...")
        request_tokens(ecobee_service)

    sum_err_cnt = 0
    sum_err_occurred = True  # Falsely assume error here to initiate loop
    timeout_err_occurred = False  # flag to indicate connection timeout occurred
    while sum_err_occurred and sum_err_cnt <= 3:
        logger.debug(F"Attempt {sum_err_cnt + 1} to retrieve thermostat summary info...")
        print(F"Attempt {sum_err_cnt + 1} to retrieve thermostat summary info...")
        sum_err_occurred = False  # Reset here to assume success this pass
        # Request the thermostat summary, which contains brief information about each thermostat,
        # including the last-reported revision interval(s)
        try:
            thermostat_summary_response = ecobee_service.request_thermostats_summary(selection=Selection(
                selection_type=SelectionType.REGISTERED.value,
                selection_match='',
                include_equipment_status=True))
        except EcobeeApiException as e:
            sum_err_cnt += 1
            sum_err_occurred = True
            # Check for error code 14, which indicates the access token has expired; if so, try to refresh
            if e.status_code == 14:
                logger.error(F"Ecobee access token expired...requesting token refresh")
                print(F"Ecobee access token expired...requesting token refresh")
                try:
                    refresh_tokens(ecobee_service)
                except EcobeeApiException as e:
                    logger.error(F"Error attempting to refresh Ecobee access token...{e}")
                    print(F"Error attempting to refresh Ecobee access token...{e}")
                    logger.debug("Refreshed access token:  " + str(ecobee_service.access_token))
                    logger.debug("Refreshed refresh token: " + str(ecobee_service.refresh_token))
                    logger.error(F"...thermostat summary API request, attempt {sum_err_cnt}")
                    print(F"...error on thermostat summary API request, attempt {sum_err_cnt}")

        except Exception as e:  # Handle no connection error
            sum_err_cnt += 1
            sum_err_occurred = True
            logger.error(F"Request error occurred during attempt to retrieve Ecobee thermostat summary...")
            logger.error(F"...error:  {e}")
            print(F"Request error occurred during attempt to retrieve Ecobee thermostat summary...")
            print(F"...error:  {e}")
            conn_err_msg = "'ConnectionError' object has no attribute 'message'"
            read_timeout_err_msg = "'ReadTimeout' object has no attribute 'message'"
            connection_timeout_err_msg = "'ConnectTimeout' object has no attribute 'message'"
            empty_return_err_msg = "Expecting value: line 1 column 1 (char 0)"
            if (conn_err_msg in e.__str__()) or \
                    (read_timeout_err_msg in e.__str__()) or \
                    (connection_timeout_err_msg in e.__str__()):
                timeout_err_occurred = True
                logger.error(F"...site not responding, or Internet connection down?")
                print(F"...site not responding, or Internet connection down?")
                logger.error(F"...thermostat summary API request, attempt {sum_err_cnt}")
                print(F"...error on thermostat summary API request, attempt {sum_err_cnt}")
            elif empty_return_err_msg in e.__str__():
                logger.error(F"...invalid return from thermostat summary API request, attempt {sum_err_cnt}")
                print(F"...invalid return from thermostat summary API request, attempt {sum_err_cnt}")
            else:
                logger.error(F"...aborting...")
                print(F"...aborting...")
                send_mail_and_exit()
    else:
        if sum_err_occurred and sum_err_cnt > 3:
            logger.error(F"Exceeded maximum retries while attempting to retrieve Ecobee thermostat summary")
            logger.error(F"...aborting (try again later)")
            print(F"...maximum retry attempts exceeded, aborting (try again later)")
            send_mail_and_exit()

        # Sample selected thermostat details
        # query_thermostat = '412825339324'         # CON1 thermostat
        query_thermostat = '416413456688'           # Test 1 thermostat
        # Template for selection types for thermostats:
        # selection = Selection(selection_type=SelectionType.REGISTERED.value, selection_match='', include_alerts=False,
        selection = Selection(selection_type=SelectionType.THERMOSTATS.value,
                              selection_match=query_thermostat,
                              include_alerts=True,
                              include_device=True,
                              include_electricity=False,
                              include_equipment_status=True,
                              include_events=False,
                              include_extended_runtime=False,
                              include_house_details=False,
                              include_location=False,
                              include_management=False,
                              include_notification_settings=False,
                              include_oem_cfg=False,
                              include_privacy=False,
                              include_program=True,
                              include_reminders=False,
                              include_runtime=False,
                              include_security_settings=False,
                              include_sensors=False,
                              include_settings=True,
                              include_technician=False,
                              include_utility=False,
                              include_version=False,
                              include_audio=False,
                              include_energy=False,
                              include_weather=False)

        try:
            print(f'Retrieving detailed thermostat settings for thermostat {query_thermostat}...')
            thermostat_response = ecobee_service.request_thermostats(selection)
        except EcobeeApiException as e:
            sum_err_cnt += 1
            sum_err_occurred = True
            if e.status_code == 14:  # Authentication error occurred
                logger.error(F"Ecobee access token expired while requesting thermostat details..."
                             F"requesting token refresh")
                print(F"Ecobee access token expired while requesting thermostat details..."
                      F"requesting token refresh")
                logger.error(F"...thermostat details API request, attempt {sum_err_cnt}")
                print(F"...error on thermostat details API request, attempt {sum_err_cnt}")
                try:
                    refresh_tokens(ecobee_service)
                    logger.info(F"Ecobee access tokens refreshed...continuing processing")
                    print(F"Ecobee access tokens refreshed...continuing processing")
                except EcobeeException as e:
                    logger.error(F"...error occurred while requesting token refresh; exiting...")
                    print(F"...error occurred while requesting token refresh; exiting...")
                    send_mail_and_exit()
        except EcobeeAuthorizationException as e:
            logger.error(F"An authorization error occurred while requesting thermostat(s) details...")
            logger.error(F"...Ecobee exception:  {e}")
            print(F"An authorization error occurred while requesting thermostat(s) details...")
            print(F"...Ecobee exception:  {e}")
            send_mail_and_exit()
        except EcobeeHttpException as e:
            logger.error(F"An HTTP error occurred while requesting thermostat(s) details...")
            logger.error(F"...Ecobee exception:  {e}")
            print(F"An HTTP error occurred while requesting thermostat(s) details...")
            print(F"...Ecobee exception:  {e}")
            send_mail_and_exit()
        except EcobeeException as e:  # Some other Ecobee API error occurred
            logger.error(F"Error occurred while requesting thermostat(s) details...")
            logger.error(F"...Ecobee exception:  {e}")
            print(F"Error occurred while requesting thermostat(s) details...")
            print(F"...Ecobee exception:  {e}")
            send_mail_and_exit()
        except Exception as e:  # Check for connection error
            sum_err_cnt += 1
            sum_err_occurred = True
            logger.error(F"Request error occurred during attempt to retrieve Ecobee thermostat details...")
            logger.error(F"...error:  {e}")
            print(F"Request error occurred during attempt to retrieve Ecobee thermostat details...")
            print(F"...error:  {e}")
            conn_err_msg = "'ConnectionError' object has no attribute 'message'"
            read_timeout_err_msg = "'ReadTimeout' object has no attribute 'message'"
            connection_timeout_err_msg = "'ConnectTimeout' object has no attribute 'message'"
            empty_return_err_msg = "Expecting value: line 1 column 1 (char 0)"
            if (conn_err_msg in e.__str__()) or \
                    (read_timeout_err_msg in e.__str__()) or \
                    (connection_timeout_err_msg in e.__str__()):
                timeout_err_occurred = True
                logger.error(F"...site not responding, or Internet connection down?")
                print(F"...site not responding, or Internet connection down?")
                logger.error(F"...thermostat details API request, attempt {sum_err_cnt}")
                print(F"...error on thermostat details API request, attempt {sum_err_cnt}")
            elif empty_return_err_msg in e.__str__():
                logger.error(F"...invalid return from thermostat detail API request, attempt {sum_err_cnt}")
                print(F"...invalid return from thermostat detail API request, attempt {sum_err_cnt}")
            else:
                send_mail_and_exit()

        # Let's send a message
        print(F"Sending message to thermostat {query_thermostat}.")
        logger.info(F"Sending message to thermostat {query_thermostat}.")
        try:
            update_thermostat_response = ecobee_service.send_message('Programmatic Testing by Keith',
                                                                     selection,
                                                                     20)        # timeout
            logger.info(update_thermostat_response.pretty_format())
        except EcobeeException as e:
            logger.error(f'Error occurred while attempting to post message to thermostat {query_thermostat}')
            logger.error(f'...error: {e}, aborting...')
            print(f'Error occurred while attempting to post message to thermostat {query_thermostat}')
            print(f'...error: {e}, aborting...')
            send_mail_and_exit()

    now = datetime.now()
    date_now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    print(F"*** Execution completed at:  {date_now_str} ***")
    logger.info(F"*** Execution completed at:  {date_now_str} ***")


def persist_to_json(auth_json_file_name, ecobee_service):
    try:
        with open(auth_json_file_name, "w") as write_auth:
            json_auth_dict['application_key'] = ecobee_service.application_key
            logger.debug(F"Persist access token:  {ecobee_service.access_token}")
            logger.debug(F"Persist refresh token:  {ecobee_service.refresh_token}")
            # print(F"Persist access token:  {ecobee_service.access_token}")
            # print(F"Persist refresh token:  {ecobee_service.refresh_token}")
            json_auth_dict['access_token'] = ecobee_service.access_token
            json_auth_dict['refresh_token'] = ecobee_service.refresh_token
            json_auth_dict['authorization_token'] = ecobee_service.authorization_token

            json.dump(json_auth_dict, write_auth)

    except Exception as e:
        logger.error(F"Error occurred while attempting to write JSON tokens file...{e}")
        logger.error(F"...aborting...")
        print(F"Error occurred while attempting to write JSON tokens file...{e}")
        print(F"...aborting...")
        send_mail_and_exit()


def refresh_tokens(ecobee_service):
    max_refresh_tkn_attempts = 3
    # Attempt refreshing the access tokens, up to the maximum retries..
    refresh_attempt = 0
    refresh_err_occurred = True  # assume failure to initiate loop
    timeout_err_occurred = False  # flag used to indicate a timeout error has occurred
    while refresh_err_occurred and (refresh_attempt <= max_refresh_tkn_attempts):
        logger.debug(F"Attempt {refresh_attempt + 1} to refresh Ecobee access tokens...")
        print(F"Attempt {refresh_attempt + 1} to refresh Ecobee access tokens...")
        refresh_err_occurred = False  # Reset error flag for this pass to assume success
        try:
            token_response = ecobee_service.refresh_tokens()
            logger.debug(F"Token response returned from refresh tokens request:  \n{token_response.pretty_format()}")
            ecobee_service.access_token = token_response.access_token
            ecobee_service.refresh_token = token_response.refresh_token
            persist_to_json(ECCAuthorize, ecobee_service)
        except EcobeeAuthorizationException as e:
            refresh_err_occurred = True
            refresh_attempt += 1
            logger.error(F"Error during request to refresh Ecobee access tokens:  {e}")
            print(F"Error during request to refresh Ecobee access tokens:  {e}")
            if 'The authorization grant, token or credentials are invalid, expired, revoked' in e.error_description:
                logger.error(F"...authorization credentials have expired or invalid")
                logger.error(F"...resetting stored authorization credentials")
                logger.error(F"...you will need to re-authorize the application in the Ecobee portal")
                print(F"...authorization credentials have expired or invalid")
                print(F"...resetting stored authorization credentials")
                print(F"...you will need to re-authorize the application in the Ecobee portal")
                # Remove the old authorization token JSON file in preparation for reauthorization
                try:
                    os.remove(ECCAuthorize)
                    logger.info(F"Ecobee authorization credentials files removed successfully")
                except Exception as e:
                    logger.error(F"Error occurred deleting authorization credentials file:  {e}")
                    print(F"Error occurred deleting authorization credentials file:  {e}")
                    send_mail_and_exit()
                authorize(ecobee_service)
        except EcobeeException as e:
            refresh_err_occurred = True
            refresh_attempt += 1
            logger.error(F"Error during request to refresh Ecobee access tokens:  {e}")
            print(F"Error during request to refresh Ecobee access tokens:  {e}")
        except Exception as e:
            refresh_err_occurred = True
            refresh_attempt += 1
            logger.error(F"Error occurred during request to refresh Ecobee access tokens:  {e}")
            print(F"Error occurred during request to refresh Ecobee access tokens:  {e}")
            conn_err_msg = "'ConnectionError' object has no attribute 'message'"
            read_timeout_err_msg = "'ReadTimeout' object has no attribute 'message'"
            connection_timeout_err_msg = "'ConnectTimeout' object has no attribute 'message'"
            if (conn_err_msg in e.__str__()) or \
                    (read_timeout_err_msg in e.__str__()) or \
                    (connection_timeout_err_msg in e.__str__()):
                timeout_err_occurred = True
    else:
        if refresh_err_occurred and (refresh_attempt > max_refresh_tkn_attempts):
            logger.error(F"Maximum retry attempts exceeded while attempting to refresh Ecobee access tokens")
            logger.error(F"...aborting...")
            print(F"Maximum retry attempts exceeded while attempting to refresh Ecobee access tokens")
            print(F"...aborting...")
            send_mail_and_exit()


def request_tokens(ecobee_service):
    try:
        token_response = ecobee_service.request_tokens()
        logger.debug(F"Token response returned from request tokens API call:  \n{token_response.pretty_format()}")
        ecobee_service.access_token = token_response.access_token
        ecobee_service.refresh_token = token_response.refresh_token
        persist_to_json(ECCAuthorize, ecobee_service)
    except EcobeeAuthorizationException as e:
        logger.error(F"Authorization error occurred while requesting Ecobee access tokens:  {e}")
        print(F"Authorization error occurred while requesting Ecobee access tokens:  {e}")
        if 'authorization has expired' in e.error_description:
            logger.error(F"...the prior authorization has expired waiting for user to authorize.")
            logger.error(F"...attempting re-authorization")
            print(F"...the prior authorization has expired waiting for user to authorize.")
            print(F"...attempting re-authorization")
            try:
                authorize(ecobee_service)
            except EcobeeException as e:
                logger.error(F"...error occurred while attempting to re-authorize Ecobee API, aborting:  {e}")
                print(F"...error occurred while attempting to re-authorize Ecobee API, aborting:  {e}")
                send_mail_and_exit()
        if 'Waiting for user to authorize' in e.error_description:
            logger.error(F"...waiting for user to authorize application...please log into Ecobee.com "
                         F"and authorize application with PIN as directed, then re-run this application to "
                         F"continue.")
            print(F"...waiting for user to authorize application...please log into Ecobee.com "
                  F"and authorize application with PIN as directed, then re-run this application to "
                  F"continue.")
            send_mail_and_exit()
    except EcobeeException as e:
        logger.error(F"Error during request for Ecobee access tokens, aborting:  {e}")
        print(F"Error during request for Ecobee access tokens, aborting:  {e}")
        send_mail_and_exit()
    except Exception as e:
        if 'ConnectionError' in e.__str__():
            logger.error(F"Error during request for Ecobee access tokens...error connecting to service...")
            logger.error(F"...error:  {e}, aborting...")
            print(F"Error during request for Ecobee access tokens...error connecting to service...")
            print(F"...error:  {e}, aborting...")
        else:
            logger.error(F"Error during request for Ecobee access tokens, aborting:  {e}")
            print(F"Error during request for Ecobee access tokens, aborting:  {e}")
        send_mail_and_exit()


def authorize(ecobee_service):
    try:
        authorize_response = ecobee_service.authorize()
        logger.debug(F"Authorize response returned from authorize API call:  \n{authorize_response.pretty_format()}")
        persist_to_json(ECCAuthorize, ecobee_service)
        logger.info(
            F"...Please go to Ecobee.com, login to the web portal and click on the settings tab. Ensure the 'My ")
        logger.info(
            F"Apps' widget is enabled. If it is not click on the 'My Apps' option in the menu on the left.")
        logger.info(
            F"Under the My Apps display, select the 'ECC Ecobee Python Set Thermostat' app, and click on the")
        logger.info(
            F"'Add Application' button on the bottom of the screen.  When prompted to 'Enter your 9 digit")
        logger.info(
            F"pin to install your third party app', paste {authorize_response.ecobee_pin} in the textbox, and")
        logger.info(
            F"then click 'Install App'.  The next screen will display any permissions the app requires and will")
        logger.info(
            F"ask you to click 'Authorize' to add the application.")
        logger.info(F"...After completing this step please re-run this application to continue.")

        print(F"Application needs to be re-authorized.  Check log for further details.")

        ecobee_service.authorization_token = authorize_response.code
        # Clear the access and refresh tokens, as these are no longer valid with a re-authorization of
        # the app and will need to be requested again on next run
        ecobee_service.access_token = ''
        ecobee_service.refresh_token = ''
        # Save the new PIN to the JSON tokens file...this is a handy reference as a backup for the log file
        # for re-authorizing the app on the Ecobee portal
        json_auth_dict['PIN'] = authorize_response.ecobee_pin
        persist_to_json(ECCAuthorize, ecobee_service)
        send_mail_and_exit()

    except EcobeeApiException as e:
        logger.error(F"Error during request for authorization of Ecobee service, aborting:  {e}")
        print(F"Error during request for authorization of Ecobee service, aborting:  {e}")
        send_mail_and_exit()
    except Exception as e:
        logger.error(F"Error occurred during request for authorization of Ecobee service...aborting.")
        logger.error(F"...error was:  {e}")
        print(F"Error occurred during request for authorization of Ecobee service...aborting.")
        print(F"...error was:  {e}")
        send_mail_and_exit()


def get_api():
    """
        This routine will attempt to read the default API key from the specified external file.
                Written by DK Fowler ... 02-Jan-2020
        :return api_key:    Default Ecobee API key read from specified external file

    """
    try:
        with open(ECCEcobeeAPIkey, 'r', encoding='utf-8') as f:
            try:
                api_key = f.readline(32)  # default API key should be 32 bytes in length
                return api_key
            except Exception as e:
                logger.error(
                    F"Error occurred during attempt to read default Ecobee set thermostat API key from file...")
                logger.error(F"...error:  {e}")
                logger.error(F"...aborting...")
                print(F"Error occurred during attempt to read default Ecobee set thermostat API key from file...")
                print(F"...error:  {e}")
                print(F"...aborting...")
                send_mail_and_exit()
    except Exception as e:
        logger.error(F"Error during attempt to open default Ecobee set thermostat API key file...{e}")
        logger.error(F"...aborting...")
        print(F"Error during attempt to open default Ecobee set thermostat API key file...{e}")
        print(F"...aborting...")
        send_mail_and_exit()


def get_email_credentials():
    """
        This routine will attempt to read the email originator username and password
        from the specified external file.
                Written by DK Fowler ... 13-Aug-2020
        :return username:    GMail originator username read from specified external file
        :return password:    GMail originator password read from specified external file

    """
    try:
        with open(ECCEcobee_gmail_credentials, 'r', encoding='utf-8') as f:
            try:
                # Credential file should contain 1 line, in the format of
                # username, password
                creds_line = f.readline()

                # Now parse the line read for the username, password
                creds = creds_line.split(',')
                return creds
            except Exception as e:
                logger.error(F"Error occurred during attempt to read ECC GMail credentials from file...")
                logger.error(F"...error:  {e}")
                logger.error(F"...aborting...")
                print(F"Error occurred during attempt to read ECC GMail credentials from file...")
                print(F"...error:  {e}")
                print(F"...aborting...")
                sys.exit(1)
    except Exception as e:
        logger.error(F"Error during attempt to open ECC GMail credentials file...{e}")
        logger.error(F"...aborting...")
        print(F"Error during attempt to open ECC GMail credentials file...{e}")
        print(F"...aborting...")
        sys.exit(1)


def send_mail(mail_origin,
              mail_pass,
              mail_local_host,
              mail_subject,
              mail_from,
              mail_to,
              mail_body):
    """
        This routine will send an e-mail message using the passed parameters.
                Written by DK Fowler ... 12-Aug-2020
        Modified to include local host name for the sender if specified.
                Modified by DK Fowler ... 21-Nov-2020
    :param mail_origin      e-mail address of the originator
    :param mail_pass        e-mail password for the originator account
    :param mail_local_host  local host name for sender domain, if specified
    :param mail_subject     e-mail subject string
    :param mail_from        e-mail from string, preceding 'From' e-mail address
    :param mail_to          e-mail 'To' destination address
    :param mail_body        e-mail message body
    :return:                True if successful, else False
    """

    mail_time = datetime.now()
    mail_time_str = mail_time.strftime("%a, %d %b %Y %H:%M:%S")
    # Get timezone offset
    # Append to date/time string; timezone must be specified as a 4-digit value, with leading
    # zeroes, such as '-0500' for EDT.
    mail_time_str = mail_time_str + " -" + f'{(time.timezone / 3600):02.0f}00'

    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465,
                                  local_hostname=mail_local_host)
        # use the following for ECC...
        # server = smtplib.SMTP_SSL('smtp-relay.gmail.com', 465)
    except smtplib.SMTPException as e:
        print(F"SMTP error occurred during attempt to connect to GMAIL, error:  {e}")
        logger.error(F"SMTP error occurred during attempt to connect to GMAIL, error:  {e}")
        return False
    except Exception as e:
        print(F"Error occurred during attempt to connect to GMAIL, error:  {e}")
        logger.error(F"Error occurred during attempt to connect to GMAIL, error:  {e}")
        return False

    # Instantiate the email message object
    msg = EmailMessage()

    # Set the message contents
    msg['Date'] = mail_time_str
    msg['Subject'] = mail_subject
    msg['From'] = mail_from + ' <' + mail_origin + '>'
    msg['To'] = 'ECC IoT Tech Group <' + mail_to + '>'
    msg.set_content(mail_body)

    try:
        server.login(mail_origin, mail_pass)
    except smtplib.SMTPException as e:
        print(F"SMTP error occurred during attempt to login to GMAIL account, error: {e}")
        logger.error(F"SMTP error occurred during attempt to login to GMAIL account, error: {e}")
        server.quit()
        return False
    except Exception as e:
        print(F"Error occurred during attempt to login to GMAIL account, error: {e}")
        logger.error(F"Error occurred during attempt to login to GMAIL account, error: {e}")
        server.quit()
        return False
    try:
        server.send_message(msg)
        print(F"Notification message successfully sent!\n\n")
        logger.info(F"Notification message successfully sent!")
    except smtplib.SMTPException as e:
        print(F"SMTP error occurred during attempt to send GMAIL message, error:  {e}")
        logger.error(F"SMTP error occurred during attempt to send GMAIL message, error:  {e}")
        return False
    except Exception as e:
        print(F"Error occurred during attempt to send GMAIL message, error:  {e}")
        logger.error(F"Error occurred during attempt to send GMAIL message, error:  {e}")
        return False

    server.quit()
    return True


def send_mail_and_exit():
    """
        This routine will send an error e-mail message then abort with an error
        code.  It is intended as a generic handler to alert administrators that a
        fatal error condition has occurred with the routine and needs attention.
                Written by DK Fowler ... 21-Nov-2020
    :return:    None
    """

    # Get the email credentials
    mail_origin, mail_pass, mail_local_host, mail_to = get_email_credentials()

    mail_subject = 'ECC Ecobee Send Message Application Failure'
    mail_from = 'ECC Ecobee Send Message App'
    # mail_to is now read from the credentials file ... 21-Nov-2020
    # For me locally...
    # mail_to = 'keith.fowler.kf+ecobee_set_thermostat@gmail.com'
    # For ECC...
    # mail_to = 'temp-sensors@epiphanycatholicchurch.org'
    mail_body = f'\nA fatal error has occurred with the ECC Ecobee Set Thermostat routine. ' \
                f'\nCheck the log file for further details.\n '

    gmail_send_status = send_mail(mail_origin,
                                  mail_pass,
                                  mail_local_host,
                                  mail_subject,
                                  mail_from,
                                  mail_to,
                                  mail_body)

    if not gmail_send_status:
        # save the datetime of the last notification
        logger.error(F"An error occurred while attempting to send abort e-mail...")

    sys.exit(1)


if __name__ == '__main__':
    main()
