#!/usr/bin/env bash
set -e

# Remove any cruft from a requirements file generated by pip-compile which we don't want to keep

function show_help {
    echo "Usage: post-pip-compile.sh file ..."
    echo "Remove any cruft left behind by pip-compile in the given requirements file(s)."
    echo ""
    echo "Removes \"-e\" prefixes which were added to GitHub URLs only so that"
    echo "pip-compile could process them correctly."
}

function clean_file {
    FILE_PATH=$1
    TEMP_FILE=${FILE_PATH}.tmp
    # Workaround for https://github.com/jazzband/pip-tools/issues/204 -
    # change absolute paths for local editable packages back to relative ones
    FILE_CONTENT=$(<${FILE_PATH})
    FILE_URL_REGEX="-e (file:///[^"$'\n'"]*)/common/lib/xmodule"
    if [[ "${FILE_CONTENT}" =~ ${FILE_URL_REGEX} ]]; then
        BASE_FILE_URL=${BASH_REMATCH[1]}
        sed "s|$BASE_FILE_URL/||" ${FILE_PATH} > ${TEMP_FILE}
        mv ${TEMP_FILE} ${FILE_PATH}
        sed "s|$BASE_FILE_URL|.|" ${FILE_PATH} > ${TEMP_FILE}
        mv ${TEMP_FILE} ${FILE_PATH}
    fi
    # Code sandbox local package installs must be non-editable due to file
    # permissions issues.  edxapp ones must stay editable until assorted
    # packaging bugs are fixed.
    if [[ "${FILE_PATH}" == "requirements/edx-sandbox/py38.txt" ]]; then
        sed "s|-e common/lib/|common/lib/|" ${FILE_PATH} > ${TEMP_FILE}
        mv ${TEMP_FILE} ${FILE_PATH}
    fi
}

for i in "$@"; do
    case ${i} in
        -h|--help)
            # help or unknown option
            show_help
            exit 0
            ;;
        *)
            clean_file ${i}
            ;;
    esac
done
