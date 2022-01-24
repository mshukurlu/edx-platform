"""
Admin site bindings for coursegraph
"""
import logging

import py2neo
from django.contrib import admin, messages
from django.utils.translation import gettext as _
from edx_django_utils.admin.mixins import ReadOnlyAdminMixin

from .models import CourseGraphCourseDump
from .tasks import ModuleStoreSerializer

log = logging.getLogger(__name__)


# Unfortunately there is no unified base class for exceptions that could come
# from Neo4j, so we do our best to collect them here in order to provide a
# better experience for admin users by catching and messaging errors instead of
# letting the request fail with a 500. But if py2neo adds a new exception class
# at some point and it slips through, oh well.
any_neo4j_error = (
    py2neo.Neo4jError,
    py2neo.ConnectionUnavailable,
    py2neo.ConnectionBroken,
    py2neo.ConnectionLimit,
    py2neo.ServiceUnavailable,
    py2neo.ProtocolError,
)


def dump_courses(modeladmin, request, queryset):
    """
    Admin action to enqueue Dump-to-CourseGraph tasks for a set of courses,
    excluding courses that haven't been published since they were last dumped.

    queryset is a QuerySet of CourseGraphCourseDump objects, which are just
    CourseOverview objects under the hood.
    """
    all_course_keys = queryset.values_list('id', flat=True)
    serializer = ModuleStoreSerializer(all_course_keys)
    try:
        submitted, skipped = serializer.dump_courses_to_neo4j()
    except any_neo4j_error as err:
        log.exception(
            "Failed to enqueue CourseGraph dumps to Neo4j (respecting cache): %s",
            ", ".join(str(course_key) for course_key in all_course_keys),
        )
        modeladmin.message_user(
            request,
            _("Error enqueueing dumps for {} course(s): {}").format(
                len(all_course_keys), str(err)
            ),
            level=messages.ERROR,
        )
        return
    if submitted:
        modeladmin.message_user(
            request,
            _(
                "Enqueued dumps for {} course(s). Skipped {} unchanged course(s)."
            ).format(len(submitted), len(skipped)),
            level=messages.SUCCESS,
        )
    else:
        modeladmin.message_user(
            request,
            _(
                "Skipped all {} course(s), as they were unchanged.",
            ).format(len(skipped)),
            level=messages.WARNING,
        )
dump_courses.short_description = _("Dump courses to CourseGraph (respect cache)")


def dump_courses_overriding_cache(modeladmin, request, queryset):
    """
    Admin action to enqueue Dump-to-CourseGraph tasks for a set of courses
    (whether or not they have been published recently).

    queryset is a QuerySet of CourseGraphCourseDump objects, which are just
    CourseOverview objects under the hood.
    """
    all_course_keys = queryset.values_list('id', flat=True)
    serializer = ModuleStoreSerializer(all_course_keys)
    try:
        submitted, _skipped = serializer.dump_courses_to_neo4j(override_cache=True)
    except any_neo4j_error as err:
        log.exception(
            "Failed to enqueue CourseGraph Neo4j course dumps (overriding cache): %s",
            ", ".join(str(course_key) for course_key in all_course_keys),
        )
        modeladmin.message_user(
            request,
            _("Error enqueueing dumps for {} course(s): {}").format(
                len(all_course_keys), str(err)
            ),
            level=messages.ERROR,
        )
        return
    modeladmin.message_user(
        request,
        _("Enqueued dumps for {} course(s).").format(len(submitted)),
        level=messages.SUCCESS,
    )
dump_courses_overriding_cache.short_description = _("Dump courses to CourseGraph (override cache)")


class CourseGraphCourseDumpAdmin(ReadOnlyAdminMixin, admin.ModelAdmin):
    """
    Model admin for "Course graph course dumps".

    Just a read-only table with some useful metadata, allowing admin users to
    select courses to be dumped to CourseGraph.
    """
    list_display = [
        'id',
        'display_name',
        'modified',
        'enrollment_start',
        'enrollment_end',
    ]
    search_fields = ['id', 'display_name']
    actions = [dump_courses, dump_courses_overriding_cache]


admin.site.register(CourseGraphCourseDump, CourseGraphCourseDumpAdmin)
