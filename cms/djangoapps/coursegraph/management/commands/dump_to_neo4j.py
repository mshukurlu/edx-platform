"""
This file contains a management command for exporting the modulestore to
neo4j, a graph database.
"""


import logging
from textwrap import dedent

from django.core.management.base import BaseCommand

from cms.djangoapps.coursegraph.tasks import ModuleStoreSerializer

log = logging.getLogger(__name__)


class Command(BaseCommand):
    """
    Dump course(s) from Modulestore over to a "CourseGraph" (Neo4j) instance.

    Example usage:
      python manage.py cms dump_to_neo4j --host localhost --port 7473 \
        --secure --user user --password password --settings=production
    """
    help = dedent(__doc__).strip()

    def add_arguments(self, parser):
        parser.add_argument(
            '--host',
            type=str,
            help="The hostname of the Neo4j server.",
        )
        parser.add_argument(
            '--port',
            type=int,
            default=7687,
            help="The port on the Neo4j server that accepts Bolt requests.",
        )
        parser.add_argument(
            '--secure',
            action='store_true',
            help="Connect to server over Bolt/TLS instead of plain unencrypted Bolt.",
        )
        parser.add_argument(
            '--user',
            type=str,
            help="The username of the Neo4j user.",
        )
        parser.add_argument(
            '--password',
            type=str,
            help="The password of the Neo4j user.",
        )
        parser.add_argument(
            '--courses',
            type=str,
            nargs='*',
            help=(
                "Keys of courses to serialize. " +
                "If not specified, all courses in the modulestore are serialized."
            ),
        )
        parser.add_argument(
            '--skip',
            type=str,
            nargs='*',
            help="Keys of courses to NOT to serialize.",
        )
        parser.add_argument(
            '--override',
            action='store_true',
            help=(
                "Dump all courses regardless of when they were last published. " +
                "By default, courses that have been dumped since last publish are skipped."
            ),
        )

    def handle(self, *args, **options):
        """
        Iterates through each course, serializes them into graphs, and saves
        those graphs to neo4j.
        """

        mss = ModuleStoreSerializer.create(options['courses'], options['skip'])

        submitted_courses, skipped_courses = mss.dump_courses_to_neo4j(
            options, override_cache=options['override']
        )

        log.info(
            "%d courses submitted for export to neo4j. %d courses skipped.",
            len(submitted_courses),
            len(skipped_courses),
        )

        if not submitted_courses:
            print("No courses submitted for export to neo4j at all!")
            return

        if submitted_courses:
            print(
                "These courses were submitted for export to neo4j successfully:\n\t" +
                "\n\t".join(submitted_courses)
            )
