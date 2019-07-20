import os
APP_ROOT = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    # UPLOAD PARAMETERS
    UPLOAD_FOLDER = os.path.join(APP_ROOT, 'app/uploads')
    IMAGE_FOLDER = os.path.join(APP_ROOT, 'app/websites')
    TEMP_FOLDER = os.path.join(APP_ROOT, 'app/tmp')
    MAX_CONTENT_LENGTH = 32 * 1024 * 1024

    # SQL PARAMETERS
    #SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    #SQLALCHEMY_TRACK_MODIFICATIONS = False
