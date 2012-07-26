from django.conf import settings
from django.http import (HttpResponse, HttpResponseForbidden, 
                         HttpResponseRedirect as redirect)
from djangohelpers.lib import rendered_with, allow_http
import feedparser
from svenweb.sites.models import (Wiki,
                                  UserWikiLocalRoles)

def requires_project_admin(func):
    def inner(request, *args, **kw):
        role = request.get_project_role()
        if "ProjectAdmin" not in role:
            return HttpResponseForbidden()
        return func(request, *args, **kw)
    return inner

@rendered_with("opencore/project_feed.rss.xml", 
               mimetype="application/rss+xml")
@allow_http("GET")
def aggregate_feed(request):
    project = request.META['HTTP_X_OPENPLANS_PROJECT']
    wikis = []
    for wiki in Wiki.objects.filter(name__startswith=project+'/'):
        perms = wiki.get_permissions(request)
        if "WIKI_VIEW" in perms and "WIKI_HISTORY" in perms:
            wikis.append(wiki)
    rss = {}
    for wiki in wikis:
        try:
            _rss = wiki.render_rss()
        except IndexError:
            continue
        rss[wiki.name] = feedparser.parse(_rss)
    
    entries = []
    while len(entries) < 5:
        candidates = []
        for wiki, feed in rss.items():
            _entries = feed['entries']
            if not len(_entries):
                continue
            candidates.append( (_entries[0]['date_parsed'], _entries[0], wiki) )
        if not len(candidates):
            break
        winner, entry, wiki = sorted(candidates, reverse=True)[0]
        rss[wiki].entries.pop(0)
        entries.append(entry)

    SITE_DOMAIN = settings.SITE_DOMAIN
    return locals()

class ValidationError(TypeError):
    def __init__(self, errors):
        self.errors = errors

def calculate_available_permissions(request):
    policy = request.get_security_policy()

    from svenweb.sites.models import PERMISSIONS
    from svenweb.opencore.security import get_permission_constraints
    member_constraints = get_permission_constraints(policy, "ProjectMember")
    other_constraints = get_permission_constraints(policy, "Authenticated")

    _member_permissions = [i for i in PERMISSIONS
                           if i[0] in member_constraints]
    _other_permissions = [i for i in PERMISSIONS
                          if i[0] in other_constraints]

    member_permissions = [(-1, "not even see this wiki")]
    for i in range(len(_member_permissions)):
        prefix = ""
        if i > 0:
            prefix = "and "
        member_permissions.append((i, prefix + _member_permissions[i][1]))
    
    other_permissions = [(-1, "not even see this wiki")]
    for i in range(len(_other_permissions)):
        prefix = ""
        if i > 0:
            prefix = "and "
        other_permissions.append((i, prefix + _other_permissions[i][1]))

    return member_permissions, other_permissions

@allow_http("GET", "POST")
@rendered_with("opencore/index.html")
def home(request):
    errors = {}
    if request.method == "POST":
        try:
            return create_wiki(request)
        except ValidationError, e:
            errors = e.errors

    project = request.META['HTTP_X_OPENPLANS_PROJECT']
    wikis = [i for i in Wiki.objects.filter(name__startswith=project+'/')
             if i.viewable(request)]

    member_permissions, other_permissions = calculate_available_permissions(request)

    return {'wikis': wikis, 'project': project,
            'wiki_managers': [request.user.username],
            'member_permissions': member_permissions,
            'other_permissions': other_permissions,
            'chosen_member_permission': member_permissions[-1][0],
            'chosen_nonmember_permission': other_permissions[-1][0],
            'errors': errors,
            }

def wiki_settings(request):
    wiki = request.site
    wiki_managers = UserWikiLocalRoles(wiki=site, roles__contains="WikiManager")
    return dict(wiki_managers=wiki_managers)

@requires_project_admin
@allow_http("POST")
def modify_wiki_settings(request, site):
    managers = request.POST.getlist("managers")
    all_roles = UserWikiLocalRoles.objects.filter(wiki=site)
    for role in all_roles:
        role.remove_role("WikiManager")
        role.save()
    for manager in managers:
        role, _ = UserWikiLocalRoles.objects.get_or_create(username=manager, wiki=site)
        role.add_role("WikiManager")
        role.save()

    member_permissions = int(request.POST.get("member_perms", "-1"))
    other_permissions = int(request.POST.get("other_perms", "-1"))

    from svenweb.sites.models import (PERMISSIONS,
                                      WikiRolePermissions)
    from svenweb.opencore.security import get_permission_constraints

    member_permissions = PERMISSIONS[:member_permissions + 1]
    other_permissions = PERMISSIONS[:other_permissions + 1]

    member_permissions = [i[0] for i in member_permissions 
                          if i[0] in get_permission_constraints(
            request,
            "ProjectMember")]

    other_permissions = [i[0] for i in other_permissions 
                          if i[0] in get_permission_constraints(
            request,
            "Authenticated")]

    p, _ = WikiRolePermissions.objects.get_or_create(wiki=site, role="ProjectMember")
    p.set_permissions(member_permissions)
    p.save()

    p, _ = WikiRolePermissions.objects.get_or_create(wiki=site, role="Authenticated")
    p.set_permissions(other_permissions)
    p.save()

    other_permissions = [i for i in other_permissions 
                          if i in get_permission_constraints(
            request,
            "Anonymous")]
    p, _ = WikiRolePermissions.objects.get_or_create(wiki=site, role="Anonymous")
    p.set_permissions(other_permissions)
    p.save()

    return

@requires_project_admin
@allow_http("GET", "POST")
@rendered_with("sites/site/configure_permissions.html")
def configure_wiki_permissions(request):
    site = request.site

    if request.method == "POST":
        modify_wiki_settings(request, site)
        return redirect(site.site_home_url())

    member_permissions, other_permissions = calculate_available_permissions(request)

    wiki_managers = [u.username for u in 
                     UserWikiLocalRoles.objects.filter(wiki=site, roles__contains="WikiManager")]

    
    from svenweb.sites.models import PERMISSIONS as _PERMISSIONS, WikiRolePermissions
    PERMISSIONS = [i[0] for i in _PERMISSIONS]
    permissions = WikiRolePermissions.objects.get(wiki=site, role="ProjectMember")
    if not permissions.get_permissions():
        chosen_member_permission = -1
    else:
        chosen_member_permission = max(PERMISSIONS.index(permission) for permission
                                       in permissions.get_permissions())
    permissions = WikiRolePermissions.objects.get(wiki=site, role="Authenticated")
    if not permissions.get_permissions():
        chosen_nonmember_permission = -1
    else:
        chosen_nonmember_permission = max(PERMISSIONS.index(permission) for permission 
                                          in permissions.get_permissions())

    return dict(site=site, path='/',
                member_permissions=member_permissions,
                other_permissions=other_permissions,
                wiki_managers=wiki_managers,
                chosen_member_permission=chosen_member_permission,
                chosen_nonmember_permission=chosen_nonmember_permission,
                )

@requires_project_admin
@allow_http("POST")
def create_wiki(request):
    _name = request.POST.get('name') or "default-wiki"
    from django.template.defaultfilters import slugify
    name = slugify(_name)
    name = request.META['HTTP_X_OPENPLANS_PROJECT'] + '/' + name
    if Wiki.objects.filter(name=name).exists():
        raise ValidationError({'name': "A wiki named %s already exists, please choose another name" % _name})

    site = Wiki(name=name)
    site.save()

    modify_wiki_settings(request, site)

    if request.FILES.get("opencore_export"):
        import_wiki(site, request.FILES['opencore_export'])

    return redirect(site.site_home_url())

import os
import tempfile
import shutil
from zipfile import ZipFile
def import_wiki(site, zipfile):
    zipfile = ZipFile(zipfile)
    prefix = zipfile.infolist()[0].filename.split("/")[0]
    assert zipfile.getinfo(prefix + "/README.txt")
    assert zipfile.getinfo(prefix + "/wiki_history/.bzr/README")

    tmpdir = tempfile.mkdtemp()
    try:
        zipfile.extractall(path=tmpdir)
        shutil.move("/%s/%s/wiki_history" % (tmpdir, prefix), site.repo_path)
    finally:
        shutil.rmtree(tmpdir)
    site.set_options({"home_page": "project-home"})
