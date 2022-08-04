"""
Instructor Dashboard Views
"""
from lib2to3.pgen2.token import EQUAL
from multiprocessing import context
from re import sub
from common.djangoapps.student.models import UserProfile
from lms.djangoapps.course_api.blocks.api import get_blocks
from lms.djangoapps.courseware.models import StudentModule as CoursewareStudentModule
from lms.djangoapps.instructor_analytics import basic as instructor_analytics_basic
import datetime
import logging
import uuid
from functools import reduce
from unittest.mock import patch
from django.http import HttpResponse
import pytz
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponseServerError
from django.urls import reverse
from django.utils.html import escape
from django.utils.translation import gettext as _
from django.utils.translation import gettext_noop
from django.views.decorators.cache import cache_control
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_POST
from edx_proctoring.api import does_backend_support_onboarding
from edx_when.api import is_enabled_for_course
from opaque_keys import InvalidKeyError
from opaque_keys.edx.keys import CourseKey
from xblock.field_data import DictFieldData
from xblock.fields import ScopeIds
from openedx.features.course_experience.utils import get_course_outline_block_tree
from common.djangoapps.course_modes.models import CourseMode, CourseModesArchive
from common.djangoapps.edxmako.shortcuts import render_to_response
from common.djangoapps.student.models import CourseEnrollment
from common.djangoapps.student.roles import (
    CourseFinanceAdminRole,
    CourseInstructorRole,
    CourseSalesAdminRole,
    CourseStaffRole
)
from common.djangoapps.util.json_request import JsonResponse
from lms.djangoapps.bulk_email.api import is_bulk_email_feature_enabled
from lms.djangoapps.certificates import api as certs_api
from lms.djangoapps.certificates.data import CertificateStatuses
from lms.djangoapps.certificates.models import (
    CertificateGenerationConfiguration,
    CertificateGenerationHistory,
    CertificateInvalidation,
    GeneratedCertificate,
    User
)
from lms.djangoapps.courseware.access import has_access
from lms.djangoapps.courseware.courses import get_studio_url
from lms.djangoapps.courseware.module_render import get_module_by_usage_id
from lms.djangoapps.discussion.django_comment_client.utils import available_division_schemes, has_forum_access
from lms.djangoapps.grades.api import is_writable_gradebook_enabled
from openedx.core.djangoapps.course_groups.cohorts import DEFAULT_COHORT_NAME, get_course_cohorts, is_course_cohorted
from openedx.core.djangoapps.discussions.config.waffle_utils import legacy_discussion_experience_enabled
from openedx.core.djangoapps.django_comment_common.models import FORUM_ROLE_ADMINISTRATOR, CourseDiscussionSettings
from openedx.core.djangoapps.site_configuration import helpers as configuration_helpers
from openedx.core.djangoapps.verified_track_content.models import VerifiedTrackCohortedCourse
from openedx.core.djangolib.markup import HTML, Text
from openedx.core.lib.courses import get_course_by_id
from openedx.core.lib.url_utils import quote_slashes
from openedx.core.lib.xblock_utils import wrap_xblock
from xmodule.html_module import HtmlBlock
from xmodule.modulestore.django import modulestore
from xmodule.tabs import CourseTab

from .. import permissions
from ..toggles import data_download_v2_is_enabled
from .tools import get_units_with_due_date, title_or_url
from lms.djangoapps.grades.api import context as grades_context
from opaque_keys.edx.keys import UsageKey
from lms.djangoapps.courseware.models import StudentModule
from django.http import JsonResponse
import json

from submissions.models import Submission
from submissions.api import get_submission_and_student

from edx_django_utils.monitoring import set_custom_attribute, set_custom_attributes_for_course_key
from django.http import  HttpResponseBadRequest
from lms.djangoapps.courseware.courses import (
    can_self_enroll_in_course,
    course_open_for_self_enrollment,
    get_course,
    get_course_date_blocks,
    get_course_overview_with_access,
    get_course_with_access,
    get_courses,
    get_current_child,
    get_permission_for_course_about,
    get_studio_url,
    sort_by_announcement,
    sort_by_start_date
)
from lms.djangoapps.courseware.exceptions import CourseAccessRedirect, Redirect
from lms.djangoapps.courseware.masquerade import setup_masquerade, is_masquerading_as_specific_student
from lms.djangoapps.course_goals.models import UserActivity
from openedx.features.course_experience.url_helpers import get_learning_mfe_home_url, is_request_from_learning_mfe
from openedx.features.course_experience.utils import dates_banner_should_display
#from lms.djangoapps.courseware.views import enclosing_sequence_for_gating_checks, get_optimization_flags_for_content

from django.shortcuts import redirect
from lms.djangoapps.edxnotes.helpers import is_feature_enabled
from lms.djangoapps.courseware.date_summary import verified_upgrade_deadline_link
from openedx.core.lib.mobile_utils import is_request_from_mobile_app
from django.views.decorators.http import require_GET, require_http_methods, require_POST
from common.djangoapps.util.views import ensure_valid_course_key, ensure_valid_usage_key
from django.views.decorators.clickjacking import xframe_options_exempt
from django.db import transaction
from lms.djangoapps.courseware.toggles import COURSEWARE_OPTIMIZED_RENDER_XBLOCK
log = logging.getLogger(__name__)




class InstructorDashboardTab(CourseTab):
    """
    Defines the Instructor Dashboard view type that is shown as a course tab.
    """

    type = "instructor"
    title = gettext_noop('Instructor')
    view_name = "instructor_dashboard"
    is_dynamic = True    # The "Instructor" tab is instead dynamically added when it is enabled

    @classmethod
    def is_enabled(cls, course, user=None):
        """
        Returns true if the specified user has staff access.
        """
        return bool(user and user.is_authenticated and user.has_perm(permissions.VIEW_DASHBOARD, course.id))


def show_analytics_dashboard_message(course_key):
    """
    Defines whether or not the analytics dashboard URL should be displayed.

    Arguments:
        course_key (CourseLocator): The course locator to display the analytics dashboard message on.
    """
    if hasattr(course_key, 'ccx'):
        ccx_analytics_enabled = settings.FEATURES.get('ENABLE_CCX_ANALYTICS_DASHBOARD_URL', False)
        return settings.ANALYTICS_DASHBOARD_URL and ccx_analytics_enabled

    return settings.ANALYTICS_DASHBOARD_URL

@ensure_csrf_cookie
@cache_control(no_cache=True,no_store=True,must_revalidate=True)
def instructor_dashboard_2_student_assisment(request,course_id,student_id,modul_id):
    #"block-v1:test-course+00001+0001+type@vertical+block@7ec8c4007e1f49fbaecea227db8aa7f4"
    #submission = get_submission_and_student("c19c62ae-570e-4a0b-bc67-a54602312af7")
    #log.info(submission)
    #return JsonResponse('ok',safe=False)
    #return JsonResponse(submission['answer'],safe=False)
    u_key = UsageKey.from_string(modul_id)
    submissionMap = {}
    userReq = None
    responseBlocks = get_blocks(
          request,
          u_key,
          userReq,
          5,
          None,
          'children,graded,format,student_view_multi_device,lti_url,due,type,display_name',
          [],
          None,
          None,
          False,)
    openassessments = []
    for item in responseBlocks:
        if item['type'] == 'openassessment':
            openassessments.append(item['id'])
       #return JsonResponse(i['id'],safe=False)

    student_submissions = StudentModule.objects.filter(module_state_key__in=openassessments).filter(student_id=student_id)

    submission_ids = []
    for submission in student_submissions:
        string_state = json.loads(submission.state)
        submission_ids.append(string_state['submission_uuid'])
        submissionMap[string_state['submission_uuid']] = {
            'submission_uuid':string_state['submission_uuid'],
            'module_state_key':str(submission.module_state_key),
            'display_name':next((x['display_name'] for x in responseBlocks if x['id'] == str(submission.module_state_key)),'Test ad'),
            'grade':submission.grade,
            'max_grade':submission.max_grade,
            'state':string_state,
            'has_saved':False,
            'saved_response_text':[],
            'saved_files_descriptions':[],
            'saved_files_names':[],
            'texts':[]
        }
        if 'has_saved' in string_state:
            submissionMap[string_state['submission_uuid']]['has_saved'] = True
            submissionMap[string_state['submission_uuid']]['saved_response_text'] = json.loads(string_state['saved_response'])
        log.info(submission.module_state_key)

    submissions = Submission.objects.filter(uuid__in=submission_ids)

    studentProfile = UserProfile.objects.filter(user_id=student_id).get()
    for submission in submissions:
        uuid = str(submission.uuid)
        submissionMap[uuid]['id'] = submission.id
        submissionMap[uuid]['submitted_at'] = str(submission.submitted_at)
        submissionMap[uuid]['texts'] = submission.answer['parts']
   # return JsonResponse(submissionMap,safe=False)

    context = {
        "submissions":submissionMap,
        "course_id":course_id,
        "studentProfile":studentProfile
    }
    return render_to_response('instructor/instructor_dashboard_2/instructor_dashboard_2_student_assessment.html',context)


def get_optimization_flags_for_content(block, fragment):
    """
    Return a dict with a set of display options appropriate for the block.

    This is going to start in a very limited way.
    """
    safe_defaults = {
        'enable_mathjax': True
    }

    # Only run our optimizations on the leaf HTML and ProblemBlock nodes. The
    # mobile apps access these directly, and we don't have to worry about
    # XBlocks that dynamically load content, like inline discussions.
    usage_key = block.location

    # For now, confine ourselves to optimizing just the HTMLBlock
    if usage_key.block_type != 'html':
        return safe_defaults

    if not COURSEWARE_OPTIMIZED_RENDER_XBLOCK.is_enabled(usage_key.course_key):
        return safe_defaults

    inspector = XBlockContentInspector(block, fragment)
    flags = dict(safe_defaults)
    flags['enable_mathjax'] = inspector.has_mathjax_content()

    return flags

class XBlockContentInspector:
    """
    Class to inspect rendered XBlock content to determine dependencies.

    A lot of content has been written with the assumption that certain
    JavaScript and assets are available. This has caused us to continue to
    include these assets in the render_xblock view, despite the fact that they
    are not used by the vast majority of content.

    In order to try to provide faster load times for most users on most content,
    this class has the job of detecting certain patterns in XBlock content that
    would imply these dependencies, so we know when to include them or not.
    """
    def __init__(self, block, fragment):
        self.block = block
        self.fragment = fragment

    def has_mathjax_content(self):
        """
        Returns whether we detect any MathJax in the fragment.

        Note that this only works for things that are rendered up front. If an
        XBlock is capable of modifying the DOM afterwards to inject math content
        into the page, this will not catch it.
        """
        # The following pairs are used to mark Mathjax syntax in XBlocks. There
        # are other options for the wiki, but we don't worry about those here.
        MATHJAX_TAG_PAIRS = [
            (r"\(", r"\)"),
            (r"\[", r"\]"),
            ("[mathjaxinline]", "[/mathjaxinline]"),
            ("[mathjax]", "[/mathjax]"),
        ]
        content = self.fragment.body_html()
        for (start_tag, end_tag) in MATHJAX_TAG_PAIRS:
            if start_tag in content and end_tag in content:
                return True

        return False



def enclosing_sequence_for_gating_checks(block):
    """
    Return the first ancestor of this block that is a SequenceDescriptor.

    Returns None if there is no such ancestor. Returns None if you call it on a
    SequenceDescriptor directly.

    We explicitly test against the three known tag types that map to sequences
    (even though two of them have been long since deprecated and are never
    used). We _don't_ test against SequentialDescriptor directly because:

    1. A direct comparison on the type fails because we magically mix it into a
       SequenceDescriptorWithMixins object.
    2. An isinstance check doesn't give us the right behavior because Courses
       and Sections both subclass SequenceDescriptor. >_<

    Also important to note that some content isn't contained in Sequences at
    all. LabXchange uses learning pathways, but even content inside courses like
    `static_tab`, `book`, and `about` live outside the sequence hierarchy.
    """
    seq_tags = ['sequential', 'problemset', 'videosequence']

    # If it's being called on a Sequence itself, then don't bother crawling the
    # ancestor tree, because all the sequence metadata we need for gating checks
    # will happen automatically when rendering the render_xblock view anyway,
    # and we don't want weird, weird edge cases where you have nested Sequences
    # (which would probably "work" in terms of OLX import).
    if block.location.block_type in seq_tags:
        return None

    ancestor = block
    while ancestor and ancestor.location.block_type not in seq_tags:
        ancestor = ancestor.get_parent()  # Note: CourseBlock's parent is None

    if ancestor:
        # get_parent() returns a parent block instance cached on the block which does not
        # have the ModuleSystem bound to it so we need to get it again with get_block() which will set up everything.
        return block.runtime.get_block(ancestor.location)
    return None

@require_http_methods(["GET", "POST"])
@ensure_valid_usage_key
@xframe_options_exempt
@transaction.non_atomic_requests
@ensure_csrf_cookie
def render_xblock(request, usage_key_string, check_if_enrolled=True):
    """
    Returns an HttpResponse with HTML content for the xBlock with the given usage_key.
    The returned HTML is a chromeless rendering of the xBlock (excluding content of the containing courseware).
    """
    from lms.urls import RESET_COURSE_DEADLINES_NAME
    from openedx.features.course_experience.urls import COURSE_HOME_VIEW_NAME

    usage_key = UsageKey.from_string(usage_key_string)

    usage_key = usage_key.replace(course_key=modulestore().fill_in_run(usage_key.course_key))
    course_key = usage_key.course_key

    # Gathering metrics to make performance measurements easier.
    set_custom_attributes_for_course_key(course_key)
    set_custom_attribute('usage_key', usage_key_string)
    set_custom_attribute('block_type', usage_key.block_type)

    requested_view = request.GET.get('view', 'student_view')
    if requested_view != 'student_view' and requested_view != 'public_view':  # lint-amnesty, pylint: disable=consider-using-in
        return HttpResponseBadRequest(
            f"Rendering of the xblock view '{bleach.clean(requested_view, strip=True)}' is not supported."
        )

    staff_access = has_access(request.user, 'staff', course_key)

    with modulestore().bulk_operations(course_key):
        # verify the user has access to the course, including enrollment check
        try:
            course = get_course_with_access(request.user, 'load', course_key, check_if_enrolled=check_if_enrolled)
        except CourseAccessRedirect:
            raise Http404("Course not found.")  # lint-amnesty, pylint: disable=raise-missing-from

        # with course access now verified:
        # assume masquerading role, if applicable.
        # (if we did this *before* the course access check, then course staff
        #  masquerading as learners would often be denied access, since course
        #  staff are generally not enrolled, and viewing a course generally
        #  requires enrollment.)
        _course_masquerade, request.user = setup_masquerade(
            request,
            course_key,
            staff_access,
        )

        # Record user activity for tracking progress towards a user's course goals (for mobile app)
        UserActivity.record_user_activity(
            request.user, usage_key.course_key, request=request, only_if_mobile_app=True
        )

        # get the block, which verifies whether the user has access to the block.
        recheck_access = request.GET.get('recheck_access') == '1'
        block, _ = get_module_by_usage_id(
            request, str(course_key), str(usage_key), disable_staff_debug_info=True, course=course,
            will_recheck_access=recheck_access
        )

        student_view_context = request.GET.dict()
        student_view_context['show_bookmark_button'] = request.GET.get('show_bookmark_button', '0') == '1'
        student_view_context['show_title'] = request.GET.get('show_title', '1') == '1'

        is_learning_mfe = is_request_from_learning_mfe(request)
        # Right now, we only care about this in regards to the Learning MFE because it results
        # in a bad UX if we display blocks with access errors (repeated upgrade messaging).
        # If other use cases appear, consider removing the is_learning_mfe check or switching this
        # to be its own query parameter that can toggle the behavior.
        student_view_context['hide_access_error_blocks'] = is_learning_mfe and recheck_access

        enable_completion_on_view_service = False
        completion_service = block.runtime.service(block, 'completion')
        if completion_service and completion_service.completion_tracking_enabled():
            if completion_service.blocks_to_mark_complete_on_view({block}):
                enable_completion_on_view_service = True
                student_view_context['wrap_xblock_data'] = {
                    'mark-completed-on-view-after-delay': completion_service.get_complete_on_view_delay_ms()
                }

        missed_deadlines, missed_gated_content = dates_banner_should_display(course_key, request.user)

        # Some content gating happens only at the Sequence level (e.g. "has this
        # timed exam started?").
        ancestor_sequence_block = enclosing_sequence_for_gating_checks(block)
        if ancestor_sequence_block:
            context = {'specific_masquerade': is_masquerading_as_specific_student(request.user, course_key)}
            # If the SequenceModule feels that gating is necessary, redirect
            # there so we can have some kind of error message at any rate.
            if ancestor_sequence_block.descendants_are_gated(context):
                return redirect(
                    reverse(
                        'render_xblock',
                        kwargs={'usage_key_string': str(ancestor_sequence_block.location)}
                    )
                )

        fragment = block.render(requested_view, context=student_view_context)
        optimization_flags = get_optimization_flags_for_content(block, fragment)

        context = {
            'fragment': fragment,
            'course': course,
            'disable_accordion': True,
            'allow_iframing': True,
            'disable_header': True,
            'disable_footer': True,
            'disable_window_wrap': True,
            'enable_completion_on_view_service': enable_completion_on_view_service,
            'edx_notes_enabled': is_feature_enabled(course, request.user),
            'staff_access': staff_access,
            'xqa_server': settings.FEATURES.get('XQA_SERVER', 'http://your_xqa_server.com'),
            'missed_deadlines': missed_deadlines,
            'missed_gated_content': missed_gated_content,
            'has_ended': course.has_ended(),
            'web_app_course_url': reverse(COURSE_HOME_VIEW_NAME, args=[course.id]),
            'on_courseware_page': True,
            'verified_upgrade_link': verified_upgrade_deadline_link(request.user, course=course),
            'is_learning_mfe': is_learning_mfe,
            'is_mobile_app': is_request_from_mobile_app(request),
            'reset_deadlines_url': reverse(RESET_COURSE_DEADLINES_NAME),
            'render_course_wide_assets': True,

            **optimization_flags,
        }
        return render_to_response('instructor/instructor_dashboard_2/assessment/courseware-chromeless.html', context)


@ensure_csrf_cookie
@cache_control(no_cache=True,no_store=True,must_revalidate=True)
def instructor_dashboard_2_student_grades(request,course_id,student_id):
    """ Display the instructor dashboard for a course. """
    try:
        course_key = CourseKey.from_string(course_id)
    except InvalidKeyError:
        log.error("Unable to find course with course key %s while loading the Instructor Dashboard.", course_id)
        return HttpResponseServerError()

    course = get_course_by_id(course_key, depth=0)

    access = {
        'admin': request.user.is_staff,
        'instructor': bool(has_access(request.user, 'instructor', course)),
        'finance_admin': CourseFinanceAdminRole(course_key).has_user(request.user),
        'sales_admin': CourseSalesAdminRole(course_key).has_user(request.user),
        'staff': bool(has_access(request.user, 'staff', course)),
        'forum_admin': has_forum_access(request.user, course_key, FORUM_ROLE_ADMINISTRATOR),
        'data_researcher': request.user.has_perm(permissions.CAN_RESEARCH, course_key),
    }

    if not request.user.has_perm(permissions.VIEW_DASHBOARD, course_key):
        raise Http404()

    is_white_label = CourseMode.is_white_label(course_key)  # lint-amnesty, pylint: disable=unused-variable

    reports_enabled = configuration_helpers.get_value('SHOW_ECOMMERCE_REPORTS', False)  # lint-amnesty, pylint: disable=unused-variable

    sections = []
    if access['staff']:
        sections_content = [
            _section_course_info(course, access),
            _section_membership(course, access),
            _section_cohort_management(course, access),
            _section_student_admin(course, access),
        ]

        if legacy_discussion_experience_enabled(course_key):
            sections_content.append(_section_discussions_management(course, access))
        sections.extend(sections_content)

    if access['data_researcher']:
        sections.append(_section_data_download(course, access))

    analytics_dashboard_message = None
    if show_analytics_dashboard_message(course_key) and (access['staff'] or access['instructor']):
        # Construct a URL to the external analytics dashboard
        analytics_dashboard_url = f'{settings.ANALYTICS_DASHBOARD_URL}/courses/{str(course_key)}'
        link_start = HTML("<a href=\"{}\" rel=\"noopener\" target=\"_blank\">").format(analytics_dashboard_url)
        analytics_dashboard_message = _(
            "To gain insights into student enrollment and participation {link_start}"
            "visit {analytics_dashboard_name}, our new course analytics product{link_end}."
        )
        analytics_dashboard_message = Text(analytics_dashboard_message).format(
            link_start=link_start, link_end=HTML("</a>"), analytics_dashboard_name=settings.ANALYTICS_DASHBOARD_NAME)

        # Temporarily show the "Analytics" section until we have a better way of linking to Insights
        sections.append(_section_analytics(course, access))

    # Check if there is corresponding entry in the CourseMode Table related to the Instructor Dashboard course
    course_mode_has_price = False  # lint-amnesty, pylint: disable=unused-variable
    paid_modes = CourseMode.paid_modes_for_course(course_key)
    if len(paid_modes) == 1:
        course_mode_has_price = True
    elif len(paid_modes) > 1:
        log.error(
            "Course %s has %s course modes with payment options. Course must only have "
            "one paid course mode to enable eCommerce options.",
            str(course_key), len(paid_modes)
        )

    if access['instructor'] and is_enabled_for_course(course_key):
        sections.insert(3, _section_extensions(course))

    # Gate access to course email by feature flag & by course-specific authorization
    if is_bulk_email_feature_enabled(course_key) and (access['staff'] or access['instructor']):
        sections.append(_section_send_email(course, access))

    # Gate access to Special Exam tab depending if either timed exams or proctored exams
    # are enabled in the course

    user_has_access = any([
        request.user.is_staff,
        CourseStaffRole(course_key).has_user(request.user),
        CourseInstructorRole(course_key).has_user(request.user)
    ])
    course_has_special_exams = course.enable_proctored_exams or course.enable_timed_exams
    can_see_special_exams = course_has_special_exams and user_has_access and settings.FEATURES.get(
        'ENABLE_SPECIAL_EXAMS', False)

    if can_see_special_exams:
        sections.append(_section_special_exams(course, access))
    # Certificates panel
    # This is used to generate example certificates
    # and enable self-generated certificates for a course.
    # Note: This is hidden for all CCXs
    certs_enabled = CertificateGenerationConfiguration.current().enabled and not hasattr(course_key, 'ccx')
    if certs_enabled and access['admin']:
        sections.append(_section_certificates(course))

    openassessment_blocks = modulestore().get_items(
        course_key, qualifiers={'category': 'openassessment'}
    )
    # filter out orphaned openassessment blocks
    openassessment_blocks = [
        block for block in openassessment_blocks if block.parent is not None
    ]
    if len(openassessment_blocks) > 0 and access['staff']:
        sections.append(_section_open_response_assessment(request, course, openassessment_blocks, access))

    disable_buttons = not CourseEnrollment.objects.is_small_course(course_key)

    certificate_allowlist = certs_api.get_allowlist(course_key)
    generate_certificate_exceptions_url = reverse(
        'generate_certificate_exceptions',
        kwargs={'course_id': str(course_key), 'generate_for': ''}
    )
    generate_bulk_certificate_exceptions_url = reverse(
        'generate_bulk_certificate_exceptions',
        kwargs={'course_id': str(course_key)}
    )
    certificate_exception_view_url = reverse(
        'certificate_exception_view',
        kwargs={'course_id': str(course_key)}
    )

    certificate_invalidation_view_url = reverse(
        'certificate_invalidation_view',
        kwargs={'course_id': str(course_key)}
    )

    certificate_invalidations = CertificateInvalidation.get_certificate_invalidations(course_key)



    student_data =  UserProfile.objects.get(
        user_id=User.objects.get(username=student_id).id
        )



    context = {
        'student_id':student_id,
        'course': course,
        'course_key':course_key,
        'studio_url': get_studio_url(course, 'course'),
        'sections': sections,
        'disable_buttons': disable_buttons,
        'analytics_dashboard_message': analytics_dashboard_message,
        'certificate_allowlist': certificate_allowlist,
        'certificate_invalidations': certificate_invalidations,
        'generate_certificate_exceptions_url': generate_certificate_exceptions_url,
        'generate_bulk_certificate_exceptions_url': generate_bulk_certificate_exceptions_url,
        'certificate_exception_view_url': certificate_exception_view_url,
        'certificate_invalidation_view_url': certificate_invalidation_view_url,
        'xqa_server': settings.FEATURES.get('XQA_SERVER', "http://your_xqa_server.com"),
        'student_data':student_data
    }

    return render_to_response('instructor/instructor_dashboard_2/instructor_dashboard_2_student_grades.html', context)

@ensure_csrf_cookie
@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def instructor_dashboard_2_students(request, course_id):  # lint-amnesty, pylint: disable=too-many-statements
    """ Display the instructor dashboard for a course. """
    try:
        course_key = CourseKey.from_string(course_id)
    except InvalidKeyError:
        log.error("Unable to find course with course key %s while loading the Instructor Dashboard.", course_id)
        return HttpResponseServerError()

    course = get_course_by_id(course_key, depth=0)

    access = {
        'admin': request.user.is_staff,
        'instructor': bool(has_access(request.user, 'instructor', course)),
        'finance_admin': CourseFinanceAdminRole(course_key).has_user(request.user),
        'sales_admin': CourseSalesAdminRole(course_key).has_user(request.user),
        'staff': bool(has_access(request.user, 'staff', course)),
        'forum_admin': has_forum_access(request.user, course_key, FORUM_ROLE_ADMINISTRATOR),
        'data_researcher': request.user.has_perm(permissions.CAN_RESEARCH, course_key),
    }

    if not request.user.has_perm(permissions.VIEW_DASHBOARD, course_key):
        raise Http404()

    is_white_label = CourseMode.is_white_label(course_key)  # lint-amnesty, pylint: disable=unused-variable

    reports_enabled = configuration_helpers.get_value('SHOW_ECOMMERCE_REPORTS', False)  # lint-amnesty, pylint: disable=unused-variable

    sections = []
    if access['staff']:
        sections_content = [
            _section_course_info(course, access),
            _section_membership(course, access),
            _section_cohort_management(course, access),
            _section_student_admin(course, access),
        ]

        if legacy_discussion_experience_enabled(course_key):
            sections_content.append(_section_discussions_management(course, access))
        sections.extend(sections_content)

    if access['data_researcher']:
        sections.append(_section_data_download(course, access))

    analytics_dashboard_message = None
    if show_analytics_dashboard_message(course_key) and (access['staff'] or access['instructor']):
        # Construct a URL to the external analytics dashboard
        analytics_dashboard_url = f'{settings.ANALYTICS_DASHBOARD_URL}/courses/{str(course_key)}'
        link_start = HTML("<a href=\"{}\" rel=\"noopener\" target=\"_blank\">").format(analytics_dashboard_url)
        analytics_dashboard_message = _(
            "To gain insights into student enrollment and participation {link_start}"
            "visit {analytics_dashboard_name}, our new course analytics product{link_end}."
        )
        analytics_dashboard_message = Text(analytics_dashboard_message).format(
            link_start=link_start, link_end=HTML("</a>"), analytics_dashboard_name=settings.ANALYTICS_DASHBOARD_NAME)

        # Temporarily show the "Analytics" section until we have a better way of linking to Insights
        sections.append(_section_analytics(course, access))

    # Check if there is corresponding entry in the CourseMode Table related to the Instructor Dashboard course
    course_mode_has_price = False  # lint-amnesty, pylint: disable=unused-variable
    paid_modes = CourseMode.paid_modes_for_course(course_key)
    if len(paid_modes) == 1:
        course_mode_has_price = True
    elif len(paid_modes) > 1:
        log.error(
            "Course %s has %s course modes with payment options. Course must only have "
            "one paid course mode to enable eCommerce options.",
            str(course_key), len(paid_modes)
        )

    if access['instructor'] and is_enabled_for_course(course_key):
        sections.insert(3, _section_extensions(course))

    # Gate access to course email by feature flag & by course-specific authorization
    if is_bulk_email_feature_enabled(course_key) and (access['staff'] or access['instructor']):
        sections.append(_section_send_email(course, access))

    # Gate access to Special Exam tab depending if either timed exams or proctored exams
    # are enabled in the course

    user_has_access = any([
        request.user.is_staff,
        CourseStaffRole(course_key).has_user(request.user),
        CourseInstructorRole(course_key).has_user(request.user)
    ])
    course_has_special_exams = course.enable_proctored_exams or course.enable_timed_exams
    can_see_special_exams = course_has_special_exams and user_has_access and settings.FEATURES.get(
        'ENABLE_SPECIAL_EXAMS', False)

    if can_see_special_exams:
        sections.append(_section_special_exams(course, access))
    # Certificates panel
    # This is used to generate example certificates
    # and enable self-generated certificates for a course.
    # Note: This is hidden for all CCXs
    certs_enabled = CertificateGenerationConfiguration.current().enabled and not hasattr(course_key, 'ccx')
    if certs_enabled and access['admin']:
        sections.append(_section_certificates(course))

    openassessment_blocks = modulestore().get_items(
        course_key, qualifiers={'category': 'openassessment'}
    )
    # filter out orphaned openassessment blocks
    openassessment_blocks = [
        block for block in openassessment_blocks if block.parent is not None
    ]
    if len(openassessment_blocks) > 0 and access['staff']:
        sections.append(_section_open_response_assessment(request, course, openassessment_blocks, access))

    disable_buttons = not CourseEnrollment.objects.is_small_course(course_key)

    certificate_allowlist = certs_api.get_allowlist(course_key)
    generate_certificate_exceptions_url = reverse(
        'generate_certificate_exceptions',
        kwargs={'course_id': str(course_key), 'generate_for': ''}
    )
    generate_bulk_certificate_exceptions_url = reverse(
        'generate_bulk_certificate_exceptions',
        kwargs={'course_id': str(course_key)}
    )
    certificate_exception_view_url = reverse(
        'certificate_exception_view',
        kwargs={'course_id': str(course_key)}
    )

    certificate_invalidation_view_url = reverse(
        'certificate_invalidation_view',
        kwargs={'course_id': str(course_key)}
    )

    certificate_invalidations = CertificateInvalidation.get_certificate_invalidations(course_key)

    query_features = [
            'id', 'username', 'name', 'email', 'language', 'location',
            'year_of_birth', 'gender', 'level_of_education', 'mailing_address',
            'goals', 'enrollment_mode', 'verification_status',
            'last_login', 'date_joined', 'external_user_key'
        ]

    student_list = instructor_analytics_basic.enrolled_students_features(course_key, query_features)
    context = {
        'course': course,
        'studio_url': get_studio_url(course, 'course'),
        'sections': sections,
        'disable_buttons': disable_buttons,
        'analytics_dashboard_message': analytics_dashboard_message,
        'certificate_allowlist': certificate_allowlist,
        'certificate_invalidations': certificate_invalidations,
        'generate_certificate_exceptions_url': generate_certificate_exceptions_url,
        'generate_bulk_certificate_exceptions_url': generate_bulk_certificate_exceptions_url,
        'certificate_exception_view_url': certificate_exception_view_url,
        'certificate_invalidation_view_url': certificate_invalidation_view_url,
        'xqa_server': settings.FEATURES.get('XQA_SERVER', "http://your_xqa_server.com"),
        'student_list':student_list
    }

    return render_to_response('instructor/instructor_dashboard_2/instructor_dashboard_2_students.html', context)


@ensure_csrf_cookie
@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def instructor_dashboard_2(request, course_id):  # lint-amnesty, pylint: disable=too-many-statements
    """ Display the instructor dashboard for a course. """
    try:
        course_key = CourseKey.from_string(course_id)
    except InvalidKeyError:
        log.error("Unable to find course with course key %s while loading the Instructor Dashboard.", course_id)
        return HttpResponseServerError()

    course = get_course_by_id(course_key, depth=0)

    access = {
        'admin': request.user.is_staff,
        'instructor': bool(has_access(request.user, 'instructor', course)),
        'finance_admin': CourseFinanceAdminRole(course_key).has_user(request.user),
        'sales_admin': CourseSalesAdminRole(course_key).has_user(request.user),
        'staff': bool(has_access(request.user, 'staff', course)),
        'forum_admin': has_forum_access(request.user, course_key, FORUM_ROLE_ADMINISTRATOR),
        'data_researcher': request.user.has_perm(permissions.CAN_RESEARCH, course_key),
    }

    if not request.user.has_perm(permissions.VIEW_DASHBOARD, course_key):
        raise Http404()

    is_white_label = CourseMode.is_white_label(course_key)  # lint-amnesty, pylint: disable=unused-variable

    reports_enabled = configuration_helpers.get_value('SHOW_ECOMMERCE_REPORTS', False)  # lint-amnesty, pylint: disable=unused-variable

    sections = []
    if access['staff']:
        sections_content = [
            _section_course_info(course, access),
            _section_membership(course, access),
            _section_cohort_management(course, access),
            _section_student_admin(course, access),
        ]

        if legacy_discussion_experience_enabled(course_key):
            sections_content.append(_section_discussions_management(course, access))
        sections.extend(sections_content)

    if access['data_researcher']:
        sections.append(_section_data_download(course, access))

    analytics_dashboard_message = None
    if show_analytics_dashboard_message(course_key) and (access['staff'] or access['instructor']):
        # Construct a URL to the external analytics dashboard
        analytics_dashboard_url = f'{settings.ANALYTICS_DASHBOARD_URL}/courses/{str(course_key)}'
        link_start = HTML("<a href=\"{}\" rel=\"noopener\" target=\"_blank\">").format(analytics_dashboard_url)
        analytics_dashboard_message = _(
            "To gain insights into student enrollment and participation {link_start}"
            "visit {analytics_dashboard_name}, our new course analytics product{link_end}."
        )
        analytics_dashboard_message = Text(analytics_dashboard_message).format(
            link_start=link_start, link_end=HTML("</a>"), analytics_dashboard_name=settings.ANALYTICS_DASHBOARD_NAME)

        # Temporarily show the "Analytics" section until we have a better way of linking to Insights
        sections.append(_section_analytics(course, access))

    # Check if there is corresponding entry in the CourseMode Table related to the Instructor Dashboard course
    course_mode_has_price = False  # lint-amnesty, pylint: disable=unused-variable
    paid_modes = CourseMode.paid_modes_for_course(course_key)
    if len(paid_modes) == 1:
        course_mode_has_price = True
    elif len(paid_modes) > 1:
        log.error(
            "Course %s has %s course modes with payment options. Course must only have "
            "one paid course mode to enable eCommerce options.",
            str(course_key), len(paid_modes)
        )

    if access['instructor'] and is_enabled_for_course(course_key):
        sections.insert(3, _section_extensions(course))

    # Gate access to course email by feature flag & by course-specific authorization
    if is_bulk_email_feature_enabled(course_key) and (access['staff'] or access['instructor']):
        sections.append(_section_send_email(course, access))

    # Gate access to Special Exam tab depending if either timed exams or proctored exams
    # are enabled in the course

    user_has_access = any([
        request.user.is_staff,
        CourseStaffRole(course_key).has_user(request.user),
        CourseInstructorRole(course_key).has_user(request.user)
    ])
    course_has_special_exams = course.enable_proctored_exams or course.enable_timed_exams
    can_see_special_exams = course_has_special_exams and user_has_access and settings.FEATURES.get(
        'ENABLE_SPECIAL_EXAMS', False)

    if can_see_special_exams:
        sections.append(_section_special_exams(course, access))
    # Certificates panel
    # This is used to generate example certificates
    # and enable self-generated certificates for a course.
    # Note: This is hidden for all CCXs
    certs_enabled = CertificateGenerationConfiguration.current().enabled and not hasattr(course_key, 'ccx')
    if certs_enabled and access['admin']:
        sections.append(_section_certificates(course))

    openassessment_blocks = modulestore().get_items(
        course_key, qualifiers={'category': 'openassessment'}
    )
    # filter out orphaned openassessment blocks
    openassessment_blocks = [
        block for block in openassessment_blocks if block.parent is not None
    ]
    if len(openassessment_blocks) > 0 and access['staff']:
        sections.append(_section_open_response_assessment(request, course, openassessment_blocks, access))

    disable_buttons = not CourseEnrollment.objects.is_small_course(course_key)

    certificate_allowlist = certs_api.get_allowlist(course_key)
    generate_certificate_exceptions_url = reverse(
        'generate_certificate_exceptions',
        kwargs={'course_id': str(course_key), 'generate_for': ''}
    )
    generate_bulk_certificate_exceptions_url = reverse(
        'generate_bulk_certificate_exceptions',
        kwargs={'course_id': str(course_key)}
    )
    certificate_exception_view_url = reverse(
        'certificate_exception_view',
        kwargs={'course_id': str(course_key)}
    )

    certificate_invalidation_view_url = reverse(
        'certificate_invalidation_view',
        kwargs={'course_id': str(course_key)}
    )

    certificate_invalidations = CertificateInvalidation.get_certificate_invalidations(course_key)

    context = {
        'course': course,
        'studio_url': get_studio_url(course, 'course'),
        'sections': sections,
        'disable_buttons': disable_buttons,
        'analytics_dashboard_message': analytics_dashboard_message,
        'certificate_allowlist': certificate_allowlist,
        'certificate_invalidations': certificate_invalidations,
        'generate_certificate_exceptions_url': generate_certificate_exceptions_url,
        'generate_bulk_certificate_exceptions_url': generate_bulk_certificate_exceptions_url,
        'certificate_exception_view_url': certificate_exception_view_url,
        'certificate_invalidation_view_url': certificate_invalidation_view_url,
        'xqa_server': settings.FEATURES.get('XQA_SERVER', "http://your_xqa_server.com"),
    }

    return render_to_response('instructor/instructor_dashboard_2/instructor_dashboard_2.html', context)


## Section functions starting with _section return a dictionary of section data.

## The dictionary must include at least {
##     'section_key': 'circus_expo'
##     'section_display_name': 'Circus Expo'
## }

## section_key will be used as a css attribute, javascript tie-in, and template import filename.
## section_display_name will be used to generate link titles in the nav bar.

def _section_special_exams(course, access):
    """ Provide data for the corresponding dashboard section """
    course_key = str(course.id)
    proctoring_provider = course.proctoring_provider
    escalation_email = None
    if proctoring_provider == 'proctortrack':
        escalation_email = course.proctoring_escalation_email
    from edx_proctoring.api import is_backend_dashboard_available

    section_data = {
        'section_key': 'special_exams',
        'section_display_name': _('Special Exams'),
        'access': access,
        'course_id': course_key,
        'escalation_email': escalation_email,
        'show_dashboard': is_backend_dashboard_available(course_key),
        'show_onboarding': does_backend_support_onboarding(course.proctoring_provider),
    }
    return section_data


def _section_certificates(course):
    """Section information for the certificates panel.

    The certificates panel allows global staff to generate
    example certificates and enable self-generated certificates
    for a course.

    Arguments:
        course (Course)

    Returns:
        dict

    """
    example_cert_status = None
    html_cert_enabled = certs_api.has_html_certificates_enabled(course)
    if html_cert_enabled:
        can_enable_for_course = True
    else:
        example_cert_status = certs_api.example_certificates_status(course.id)

        # Allow the user to enable self-generated certificates for students
        # *only* once a set of example certificates has been successfully generated.
        # If certificates have been misconfigured for the course (for example, if
        # the PDF template hasn't been uploaded yet), then we don't want
        # to turn on self-generated certificates for students!
        can_enable_for_course = (
            example_cert_status is not None and
            all(
                cert_status['status'] == 'success'
                for cert_status in example_cert_status
            )
        )
    instructor_generation_enabled = settings.FEATURES.get('CERTIFICATES_INSTRUCTOR_GENERATION', False)
    certificate_statuses_with_count = {
        certificate['status']: certificate['count']
        for certificate in GeneratedCertificate.get_unique_statuses(course_key=course.id)
    }

    return {
        'section_key': 'certificates',
        'section_display_name': _('Certificates'),
        'example_certificate_status': example_cert_status,
        'can_enable_for_course': can_enable_for_course,
        'enabled_for_course': certs_api.has_self_generated_certificates_enabled(course.id),
        'is_self_paced': course.self_paced,
        'instructor_generation_enabled': instructor_generation_enabled,
        'html_cert_enabled': html_cert_enabled,
        'active_certificate': certs_api.get_active_web_certificate(course),
        'certificate_statuses_with_count': certificate_statuses_with_count,
        'status': CertificateStatuses,
        'certificate_generation_history':
            CertificateGenerationHistory.objects.filter(course_id=course.id).order_by("-created"),
        'urls': {
            'enable_certificate_generation': reverse(
                'enable_certificate_generation',
                kwargs={'course_id': course.id}
            ),
            'start_certificate_generation': reverse(
                'start_certificate_generation',
                kwargs={'course_id': course.id}
            ),
            'start_certificate_regeneration': reverse(
                'start_certificate_regeneration',
                kwargs={'course_id': course.id}
            ),
            'list_instructor_tasks_url': reverse(
                'list_instructor_tasks',
                kwargs={'course_id': course.id}
            ),
        }
    }


@ensure_csrf_cookie
@cache_control(no_cache=True, no_store=True, must_revalidate=True)
@require_POST
@login_required
def set_course_mode_price(request, course_id):
    """
    set the new course price and add new entry in the CourseModesArchive Table
    """
    try:
        course_price = int(request.POST['course_price'])
    except ValueError:
        return JsonResponse(
            {'message': _("Please Enter the numeric value for the course price")},
            status=400)  # status code 400: Bad Request

    currency = request.POST['currency']
    course_key = CourseKey.from_string(course_id)

    course_honor_mode = CourseMode.objects.filter(mode_slug='honor', course_id=course_key)
    if not course_honor_mode:
        return JsonResponse(
            {'message': _("CourseMode with the mode slug({mode_slug}) DoesNotExist").format(mode_slug='honor')},
            status=400)  # status code 400: Bad Request

    CourseModesArchive.objects.create(
        course_id=course_id, mode_slug='honor', mode_display_name='Honor Code Certificate',
        min_price=course_honor_mode[0].min_price, currency=course_honor_mode[0].currency,
        expiration_datetime=datetime.datetime.now(pytz.utc), expiration_date=datetime.date.today()
    )
    course_honor_mode.update(
        min_price=course_price,
        currency=currency
    )
    return JsonResponse({'message': _("CourseMode price updated successfully")})


def _section_course_info(course, access):
    """ Provide data for the corresponding dashboard section """
    course_key = course.id

    section_data = {
        'section_key': 'course_info',
        'section_display_name': _('Course Info'),
        'access': access,
        'course_id': course_key,
        'course_display_name': course.display_name_with_default,
        'course_org': course.display_org_with_default,
        'course_number': course.display_number_with_default,
        'has_started': course.has_started(),
        'has_ended': course.has_ended(),
        'start_date': course.start,
        'end_date': course.end,
        'num_sections': len(course.children),
        'list_instructor_tasks_url': reverse('list_instructor_tasks', kwargs={'course_id': str(course_key)}),
    }

    if settings.FEATURES.get('DISPLAY_ANALYTICS_ENROLLMENTS'):
        section_data['enrollment_count'] = CourseEnrollment.objects.enrollment_counts(course_key)

    if show_analytics_dashboard_message(course_key):
        #  dashboard_link is already made safe in _get_dashboard_link
        dashboard_link = _get_dashboard_link(course_key)
        #  so we can use Text() here so it's not double-escaped and rendering HTML on the front-end
        message = Text(
            _("Enrollment data is now available in {dashboard_link}.")
        ).format(dashboard_link=dashboard_link)
        section_data['enrollment_message'] = message

    try:
        sorted_cutoffs = sorted(list(course.grade_cutoffs.items()), key=lambda i: i[1], reverse=True)
        advance = lambda memo, letter_score_tuple: f"{letter_score_tuple[0]}: {letter_score_tuple[1]}, " \
                                                   + memo
        section_data['grade_cutoffs'] = reduce(advance, sorted_cutoffs, "")[:-2]
    except Exception:  # pylint: disable=broad-except
        section_data['grade_cutoffs'] = "Not Available"

    try:
        section_data['course_errors'] = [(escape(a), '') for (a, _unused) in modulestore().get_course_errors(course.id)]
    except Exception:  # pylint: disable=broad-except
        section_data['course_errors'] = [('Error fetching errors', '')]

    return section_data


def _section_membership(course, access):
    """ Provide data for the corresponding dashboard section """
    course_key = course.id
    ccx_enabled = settings.FEATURES.get('CUSTOM_COURSES_EDX', False) and course.enable_ccx

    section_data = {
        'section_key': 'membership',
        'section_display_name': _('Membership'),
        'access': access,
        'ccx_is_enabled': ccx_enabled,
        'enroll_button_url': reverse('students_update_enrollment', kwargs={'course_id': str(course_key)}),
        'unenroll_button_url': reverse('students_update_enrollment', kwargs={'course_id': str(course_key)}),
        'upload_student_csv_button_url': reverse(
            'register_and_enroll_students',
            kwargs={'course_id': str(course_key)}
        ),
        'modify_beta_testers_button_url': reverse(
            'bulk_beta_modify_access',
            kwargs={'course_id': str(course_key)}
        ),
        'list_course_role_members_url': reverse(
            'list_course_role_members',
            kwargs={'course_id': str(course_key)}
        ),
        'modify_access_url': reverse('modify_access', kwargs={'course_id': str(course_key)}),
        'list_forum_members_url': reverse('list_forum_members', kwargs={'course_id': str(course_key)}),
        'update_forum_role_membership_url': reverse(
            'update_forum_role_membership',
            kwargs={'course_id': str(course_key)}
        ),
        'is_reason_field_enabled': configuration_helpers.get_value('ENABLE_MANUAL_ENROLLMENT_REASON_FIELD', False)
    }
    return section_data


def _section_cohort_management(course, access):
    """ Provide data for the corresponding cohort management section """
    course_key = course.id
    ccx_enabled = hasattr(course_key, 'ccx')
    section_data = {
        'section_key': 'cohort_management',
        'section_display_name': _('Cohorts'),
        'access': access,
        'ccx_is_enabled': ccx_enabled,
        'course_cohort_settings_url': reverse(
            'course_cohort_settings',
            kwargs={'course_key_string': str(course_key)}
        ),
        'cohorts_url': reverse('cohorts', kwargs={'course_key_string': str(course_key)}),
        'upload_cohorts_csv_url': reverse('add_users_to_cohorts', kwargs={'course_id': str(course_key)}),
        'verified_track_cohorting_url': reverse(
            'verified_track_cohorting', kwargs={'course_key_string': str(course_key)}
        ),
    }
    return section_data


def _section_discussions_management(course, access):  # lint-amnesty, pylint: disable=unused-argument
    """ Provide data for the corresponding discussion management section """
    course_key = course.id
    enrollment_track_schemes = available_division_schemes(course_key)
    section_data = {
        'section_key': 'discussions_management',
        'section_display_name': _('Discussions'),
        'is_hidden': (not is_course_cohorted(course_key) and
                      CourseDiscussionSettings.ENROLLMENT_TRACK not in enrollment_track_schemes),
        'discussion_topics_url': reverse('discussion_topics', kwargs={'course_key_string': str(course_key)}),
        'course_discussion_settings': reverse(
            'course_discussions_settings',
            kwargs={'course_key_string': str(course_key)}
        ),
    }
    return section_data


def _section_student_admin(course, access):
    """ Provide data for the corresponding dashboard section """
    course_key = course.id
    is_small_course = CourseEnrollment.objects.is_small_course(course_key)

    section_data = {
        'section_key': 'student_admin',
        'section_display_name': _('Student Admin'),
        'access': access,
        'is_small_course': is_small_course,
        'get_student_enrollment_status_url': reverse(
            'get_student_enrollment_status',
            kwargs={'course_id': str(course_key)}
        ),
        'get_student_progress_url_url': reverse(
            'get_student_progress_url',
            kwargs={'course_id': str(course_key)}
        ),
        'enrollment_url': reverse('students_update_enrollment', kwargs={'course_id': str(course_key)}),
        'reset_student_attempts_url': reverse(
            'reset_student_attempts',
            kwargs={'course_id': str(course_key)}
        ),
        'reset_student_attempts_for_entrance_exam_url': reverse(
            'reset_student_attempts_for_entrance_exam',
            kwargs={'course_id': str(course_key)},
        ),
        'rescore_problem_url': reverse('rescore_problem', kwargs={'course_id': str(course_key)}),
        'override_problem_score_url': reverse(
            'override_problem_score',
            kwargs={'course_id': str(course_key)}
        ),
        'rescore_entrance_exam_url': reverse('rescore_entrance_exam', kwargs={'course_id': str(course_key)}),
        'student_can_skip_entrance_exam_url': reverse(
            'mark_student_can_skip_entrance_exam',
            kwargs={'course_id': str(course_key)},
        ),
        'list_instructor_tasks_url': reverse('list_instructor_tasks', kwargs={'course_id': str(course_key)}),
        'list_entrace_exam_instructor_tasks_url': reverse(
            'list_entrance_exam_instructor_tasks',
            kwargs={'course_id': str(course_key)}
        ),
        'spoc_gradebook_url': reverse('spoc_gradebook', kwargs={'course_id': str(course_key)}),
    }
    if is_writable_gradebook_enabled(course_key) and settings.WRITABLE_GRADEBOOK_URL:
        section_data['writable_gradebook_url'] = f'{settings.WRITABLE_GRADEBOOK_URL}/{str(course_key)}'
    return section_data


def _section_extensions(course):
    """ Provide data for the corresponding dashboard section """
    section_data = {
        'section_key': 'extensions',
        'section_display_name': _('Extensions'),
        'units_with_due_dates': [(title_or_url(unit), str(unit.location))
                                 for unit in get_units_with_due_date(course)],
        'change_due_date_url': reverse('change_due_date', kwargs={'course_id': str(course.id)}),
        'reset_due_date_url': reverse('reset_due_date', kwargs={'course_id': str(course.id)}),
        'show_unit_extensions_url': reverse('show_unit_extensions', kwargs={'course_id': str(course.id)}),
        'show_student_extensions_url': reverse(
            'show_student_extensions',
            kwargs={'course_id': str(course.id)}
        ),
    }
    return section_data


def _section_data_download(course, access):
    """ Provide data for the corresponding dashboard section """
    course_key = course.id

    show_proctored_report_button = (
        settings.FEATURES.get('ENABLE_SPECIAL_EXAMS', False) and
        course.enable_proctored_exams
    )
    section_key = 'data_download_2' if data_download_v2_is_enabled() else 'data_download'
    section_data = {
        'section_key': section_key,
        'section_display_name': _('Data Download'),
        'access': access,
        'show_generate_proctored_exam_report_button': show_proctored_report_button,
        'get_problem_responses_url': reverse('get_problem_responses', kwargs={'course_id': str(course_key)}),
        'get_grading_config_url': reverse('get_grading_config', kwargs={'course_id': str(course_key)}),
        'get_students_features_url': reverse('get_students_features', kwargs={'course_id': str(course_key)}),
        'get_issued_certificates_url': reverse(
            'get_issued_certificates', kwargs={'course_id': str(course_key)}
        ),
        'get_students_who_may_enroll_url': reverse(
            'get_students_who_may_enroll', kwargs={'course_id': str(course_key)}
        ),
        'get_anon_ids_url': reverse('get_anon_ids', kwargs={'course_id': str(course_key)}),
        'list_proctored_results_url': reverse(
            'get_proctored_exam_results', kwargs={'course_id': str(course_key)}
        ),
        'list_instructor_tasks_url': reverse('list_instructor_tasks', kwargs={'course_id': str(course_key)}),
        'list_report_downloads_url': reverse('list_report_downloads', kwargs={'course_id': str(course_key)}),
        'calculate_grades_csv_url': reverse('calculate_grades_csv', kwargs={'course_id': str(course_key)}),
        'problem_grade_report_url': reverse('problem_grade_report', kwargs={'course_id': str(course_key)}),
        'course_has_survey': True if course.course_survey_name else False,  # lint-amnesty, pylint: disable=simplifiable-if-expression
        'course_survey_results_url': reverse(
            'get_course_survey_results', kwargs={'course_id': str(course_key)}
        ),
        'export_ora2_data_url': reverse('export_ora2_data', kwargs={'course_id': str(course_key)}),
        'export_ora2_submission_files_url': reverse(
            'export_ora2_submission_files', kwargs={'course_id': str(course_key)}
        ),
        'export_ora2_summary_url': reverse('export_ora2_summary', kwargs={'course_id': str(course_key)}),
    }
    if not access.get('data_researcher'):
        section_data['is_hidden'] = True
    return section_data


def null_applicable_aside_types(block):  # pylint: disable=unused-argument
    """
    get_aside method for monkey-patching into applicable_aside_types
    while rendering an HtmlBlock for email text editing. This returns
    an empty list.
    """
    return []


def _section_send_email(course, access):
    """ Provide data for the corresponding bulk email section """
    course_key = course.id

    # Monkey-patch applicable_aside_types to return no asides for the duration of this render
    with patch.object(course.runtime, 'applicable_aside_types', null_applicable_aside_types):
        # This HtmlBlock is only being used to generate a nice text editor.
        html_module = HtmlBlock(
            course.system,
            DictFieldData({'data': ''}),
            ScopeIds(None, None, None, course_key.make_usage_key('html', 'fake'))
        )
        fragment = course.system.render(html_module, 'studio_view')
    fragment = wrap_xblock(
        'LmsRuntime', html_module, 'studio_view', fragment, None,
        extra_data={"course-id": str(course_key)},
        usage_id_serializer=lambda usage_id: quote_slashes(str(usage_id)),
        # Generate a new request_token here at random, because this module isn't connected to any other
        # xblock rendering.
        request_token=uuid.uuid1().hex
    )
    cohorts = []
    if is_course_cohorted(course_key):
        cohorts = get_course_cohorts(course)
    course_modes = []
    if not VerifiedTrackCohortedCourse.is_verified_track_cohort_enabled(course_key):
        course_modes = CourseMode.modes_for_course(course_key, include_expired=True, only_selectable=False)
    email_editor = fragment.content
    section_data = {
        'section_key': 'send_email',
        'section_display_name': _('Email'),
        'access': access,
        'send_email': reverse('send_email', kwargs={'course_id': str(course_key)}),
        'editor': email_editor,
        'cohorts': cohorts,
        'course_modes': course_modes,
        'default_cohort_name': DEFAULT_COHORT_NAME,
        'list_instructor_tasks_url': reverse(
            'list_instructor_tasks', kwargs={'course_id': str(course_key)}
        ),
        'email_background_tasks_url': reverse(
            'list_background_email_tasks', kwargs={'course_id': str(course_key)}
        ),
        'email_content_history_url': reverse(
            'list_email_content', kwargs={'course_id': str(course_key)}
        ),
    }
    return section_data


def _get_dashboard_link(course_key):
    """ Construct a URL to the external analytics dashboard """
    analytics_dashboard_url = f'{settings.ANALYTICS_DASHBOARD_URL}/courses/{str(course_key)}'
    link = HTML("<a href=\"{0}\" rel=\"noopener\" target=\"_blank\">{1}</a>").format(
        analytics_dashboard_url, settings.ANALYTICS_DASHBOARD_NAME
    )
    return link


def _section_analytics(course, access):
    """ Provide data for the corresponding dashboard section """
    section_data = {
        'section_key': 'instructor_analytics',
        'section_display_name': _('Analytics'),
        'access': access,
        'course_id': str(course.id),
    }
    return section_data


def _section_open_response_assessment(request, course, openassessment_blocks, access):
    """Provide data for the corresponding dashboard section """
    course_key = course.id

    ora_items = []
    parents = {}

    for block in openassessment_blocks:
        block_parent_id = str(block.parent)
        result_item_id = str(block.location)
        if block_parent_id not in parents:
            parents[block_parent_id] = modulestore().get_item(block.parent)
        assessment_name = _("Team") + " : " + block.display_name if block.teams_enabled else block.display_name
        ora_items.append({
            'id': result_item_id,
            'name': assessment_name,
            'parent_id': block_parent_id,
            'parent_name': parents[block_parent_id].display_name,
            'staff_assessment': 'staff-assessment' in block.assessment_steps,
            'peer_assessment': 'peer-assessment' in block.assessment_steps,
            'url_base': reverse('xblock_view', args=[course.id, block.location, 'student_view']),
            'url_grade_available_responses': reverse('xblock_view', args=[course.id, block.location,
                                                                          'grade_available_responses_view']),
            'url_waiting_step_details': reverse(
                'xblock_view',
                args=[course.id, block.location, 'waiting_step_details_view'],
            ),
        })

    openassessment_block = openassessment_blocks[0]
    block, __ = get_module_by_usage_id(
        request, str(course_key), str(openassessment_block.location),
        disable_staff_debug_info=True, course=course
    )
    section_data = {
        'fragment': block.render('ora_blocks_listing_view', context={
            'ora_items': ora_items,
            'ora_item_view_enabled': settings.FEATURES.get('ENABLE_XBLOCK_VIEW_ENDPOINT', False)
        }),
        'section_key': 'open_response_assessment',
        'section_display_name': _('Open Responses'),
        'access': access,
        'course_id': str(course_key),
    }
    return section_data


def is_ecommerce_course(course_key):
    """
    Checks if the given course is an e-commerce course or not, by checking its SKU value from
    CourseMode records for the course
    """
    sku_count = len([mode.sku for mode in CourseMode.modes_for_course(course_key) if mode.sku])
    return sku_count > 0
