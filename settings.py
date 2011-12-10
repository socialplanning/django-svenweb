# Django settings for svenweb project.

DEBUG = False
TEMPLATE_DEBUG = DEBUG

ADMINS = (
    # ('Your Name', 'your_email@example.com'),
)

MANAGERS = ADMINS

import os
here = os.path.abspath(".")

def WIKI_PERMALINK_BUILDER(wiki, bits):
    bits = list(bits)
    bits[1] = [wiki.name.split('/')[1]] + bits[1]
    return tuple(bits)

def get_permission_constraints(policy_or_request, role):
    PERMISSION_CONSTRAINTS = {
    'open_policy': {
        "Anonymous": ["WIKI_VIEW", "WIKI_HISTORY"],
        "Authenticated": ["WIKI_VIEW", "WIKI_HISTORY", "WIKI_EDIT"],
        "ProjectMember": ["WIKI_VIEW", "WIKI_HISTORY",
                          "WIKI_EDIT", "WIKI_CONFIGURE", "WIKI_DEPLOY"],
        "WikiManager": ["WIKI_VIEW", "WIKI_HISTORY",
                        "WIKI_EDIT", "WIKI_CONFIGURE", "WIKI_DEPLOY"],
        "ProjectAdmin": ["WIKI_VIEW", "WIKI_HISTORY",
                         "WIKI_EDIT", "WIKI_CONFIGURE", "WIKI_DEPLOY"],
        },
    'medium_policy': {
        "Anonymous": ["WIKI_VIEW", "WIKI_HISTORY"],
        "Authenticated": ["WIKI_VIEW", "WIKI_HISTORY"],
        "ProjectMember": ["WIKI_VIEW", "WIKI_HISTORY",
                          "WIKI_EDIT", "WIKI_CONFIGURE", "WIKI_DEPLOY"],
        "WikiManager": ["WIKI_VIEW", "WIKI_HISTORY",
                        "WIKI_EDIT", "WIKI_CONFIGURE", "WIKI_DEPLOY"],
        "ProjectAdmin": ["WIKI_VIEW", "WIKI_HISTORY",
                         "WIKI_EDIT", "WIKI_CONFIGURE", "WIKI_DEPLOY"],
        },
    'closed_policy': {
        "Anonymous": [],
        "Authenticated": [],
        "ProjectMember": ["WIKI_VIEW", "WIKI_HISTORY",
                          "WIKI_EDIT", "WIKI_CONFIGURE", "WIKI_DEPLOY"],
        "WikiManager": ["WIKI_VIEW", "WIKI_HISTORY",
                        "WIKI_EDIT", "WIKI_CONFIGURE", "WIKI_DEPLOY"],
        "ProjectAdmin": ["WIKI_VIEW", "WIKI_HISTORY",
                         "WIKI_EDIT", "WIKI_CONFIGURE", "WIKI_DEPLOY"],
        },
    }
    if isinstance(policy_or_request, basestring):
        policy = policy_or_request
    else:
        policy = policy_or_request.get_security_policy()
    return PERMISSION_CONSTRAINTS[policy][role]

def get_highest_role(roles):
    for role in (
        "ProjectAdmin",
        "WikiManager",
        "ProjectMember",
        "Authenticated",
        "Anonymous",
        ):
        if role in roles:
            return role

SVENWEB_PERMISSION_CONSTRAINT_GETTER = get_permission_constraints
SVENWEB_HIGHEST_ROLE_FINDER = get_highest_role
SVENWEB_EXTRA_ROLE_GETTER = lambda req, wiki: req.get_project_role()

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3', # Add 'postgresql_psycopg2', 'postgresql', 'mysql', 'sqlite3' or 'oracle'.
        'NAME': 'svenweb',              # Or path to database file if using sqlite3.
        'USER': '',                      # Not used with sqlite3.
        'PASSWORD': '',                  # Not used with sqlite3.
        'HOST': '',                      # Set to empty string for localhost. Not used with sqlite3.
        'PORT': '',                      # Set to empty string for default. Not used with sqlite3.
    }
}

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# On Unix systems, a value of None will cause Django to use the same
# timezone as the operating system.
# If running in a Windows environment this must be set to the same as your
# system time zone.
TIME_ZONE = 'America/Chicago'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en-us'

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale
USE_L10N = True

# Absolute filesystem path to the directory that will hold user-uploaded files.
# Example: "/home/media/media.lawrence.com/media/"
MEDIA_ROOT = ''

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://media.lawrence.com/media/", "http://example.com/media/"
MEDIA_URL = ''

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
# Example: "/home/media/media.lawrence.com/static/"
STATIC_ROOT = ''

# URL prefix for static files.
# Example: "http://media.lawrence.com/static/"
STATIC_URL = '/static/'

# URL prefix for admin static files -- CSS, JavaScript and images.
# Make sure to use a trailing slash.
# Examples: "http://foo.com/static/admin/", "/static/admin/".
ADMIN_MEDIA_PREFIX = '/static/admin/'

# Additional locations of static files
STATICFILES_DIRS = (
    # Put strings here, like "/home/html/static" or "C:/www/django/static".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
)

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
#    'django.contrib.staticfiles.finders.DefaultStorageFinder',
)

# Make this unique, and don't share it with anybody.
SECRET_KEY = 'qm7livob6w)w!)x8&chydmm-7k7_kbqb3o1xu6q4_l^mpo7%5z'

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
#     'django.template.loaders.eggs.Loader',
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.middleware.transaction.TransactionMiddleware',
    'svenweb.opencore.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'svenweb.sites.middleware.SvenwebSecurityMiddleware',
    'svenweb.opencore.middleware.SiteContextMiddleware',
)
OPENCORE_SHARED_SECRET_FILE = '../../../../../var/secret.txt'
OPENCORE_ADMIN_FILE = '../../../../../var/admin.txt'
OPENCORE_SERVER = 'http://localhost:10000'

AUTHENTICATION_BACKENDS = ()

TEMPLATE_CONTEXT_PROCESSORS = (
    'django.core.context_processors.request',
    "django.contrib.auth.context_processors.auth",
    "django.core.context_processors.debug",
    "django.core.context_processors.i18n",
    "django.core.context_processors.media",
    "django.core.context_processors.static",
    "django.contrib.messages.context_processors.messages")

ROOT_URLCONF = 'svenweb.opencore.urls'

TEMPLATE_DIRS = (
    'templates',
)

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.admin',
    'svenweb.sites',
    'svenweb.opencore',
    'djsupervisor',
    'gunicorn',
)

# A sample logging configuration. The only tangible logging
# performed by this configuration is to send an email to
# the site admins on every HTTP 500 error.
# See http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'mail_admins': {
            'level': 'ERROR',
            'class': 'django.utils.log.AdminEmailHandler'
        }
    },
    'loggers': {
        'django.request': {
            'handlers': ['mail_admins'],
            'level': 'ERROR',
            'propagate': True,
        },
    }
}

SVENWEB_REPO_PATH = 'repos'

try:
    from local_settings import *
except ImportError:
    pass
