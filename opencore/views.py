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

@allow_http("GET")
def aggregate_feed(request):
    project = request.META['HTTP_X_OPENPLANS_PROJECT']
    wikis = []
    for wiki in Wiki.objects.filter(name__startswith=project+'/'):
        perms = wiki.get_permissions(request)
        if "WIKI_VIEW" in perms and "WIKI_HISTORY" in perms:
            wikis.append(wiki)
    rss = []
    for wiki in wikis:
        try:
            _rss = wiki.render_rss()
        except IndexError:
            continue
        rss.append(_rss)
    
    #decorated = [(entry['feed']["date_parsed"], entry) for entry in rss]
    #decorated.sort()
    #decorated.reverse()
    #sorted = [entry for (date,entry) in decorated]

    return HttpResponse(rss[-1], content_type="application/rss+xml")

@allow_http("GET", "POST")
@rendered_with("opencore/index.html")
def home(request):
    if request.method == "POST":
        return create_wiki(request)

    project = request.META['HTTP_X_OPENPLANS_PROJECT']
    wikis = [i for i in Wiki.objects.filter(name__startswith=project+'/')
             if i.viewable(request)]

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
    
    return {'wikis': wikis, 'project': project,
            'wiki_managers': [request.user.username],
            'member_permissions': member_permissions,
            'other_permissions': other_permissions,
            'chosen_member_permission': member_permissions[-1][0],
            'chosen_nonmember_permission': other_permissions[-1][0],
            }

def wiki_settings(request):
    wiki = request.site
    wiki_managers = UserWikiLocalRoles(wiki=site, roles__contains="WikiManager")
    return dict(wiki_managers=wiki_managers)

@requires_project_admin
@allow_http("POST")
def create_wiki(request):
    name = request.POST.get('name') or "default-wiki"
    from django.template.defaultfilters import slugify
    name = slugify(name)
    name = request.META['HTTP_X_OPENPLANS_PROJECT'] + '/' + name
    site = Wiki(name=name)
    site.save()

    managers = request.POST.getlist("managers")
    for manager in managers:
        role = UserWikiLocalRoles(username=manager, wiki=site)
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

    p = WikiRolePermissions(wiki=site, role="ProjectMember")
    p.set_permissions(member_permissions)
    p.save()

    p = WikiRolePermissions(wiki=site, role="Authenticated")
    p.set_permissions(other_permissions)
    p.save()

    other_permissions = [i for i in other_permissions 
                          if i in get_permission_constraints(
            request,
            "Anonymous")]
    p = WikiRolePermissions(wiki=site, role="Anonymous")
    p.set_permissions(other_permissions)
    p.save()

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
