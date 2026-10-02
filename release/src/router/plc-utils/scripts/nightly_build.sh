#!/bin/sh

GIT_PROJECT="plc-utils"

if [ $# -eq 1 ]; then
	GIT_PROJECT="${1}"
fi

if [ $# -gt 1 ]; then
	echo "usage: ${0} [project_name]"
	exit 1
fi

GIT_BINARY="/usr/local/bin/git"

GIT_ROOT="ssh://appslinux01.qca.qualcomm.com/home/git/${GIT_PROJECT}"

FAILURE_EMAIL_LIST="nhoughto@qca.qualcomm.com cmaier@qca.qualcomm.com michmonr@qca.qualcomm.com"
SUCCESS_EMAIL_LIST="nhoughto@qca.qualcomm.com cmaier@qca.qualcomm.com michmonr@qca.qualcomm.com"
NOCHANGE_EMAIL_LIST="nhoughto@qca.qualcomm.com"

DEST_ROOT="${HOME}/nightly_build/${GIT_PROJECT}"

DEST_SOURCE="${DEST_ROOT}/source/"
DEST_BINARY="${DEST_ROOT}/binary/"
NIGHTLY_LOG="${DEST_ROOT}/nightly.log"
REPORT_FILE="${DEST_ROOT}/report.log"
LAST_BUILD_FILE="${DEST_ROOT}/last_build"

if [ -z "$(uname -a | grep BSD)" ]; then
	MAKE_PROGRAM="make"
else
	MAKE_PROGRAM="gmake"
fi

if [ -z "$(uname -a | grep "Cygwin")" ]; then
	CYGWIN=0
else
	CYGWIN=1
	GIT_BINARY="/usr/bin/git"
fi

heading()
{
	echo
	echo "===> ${1}"
	echo
}

nightly_setup()
{
	mkdir -p "${DEST_SOURCE}" "${DEST_BINARY}"
	if [ $? -ne 0 ]; then
		echo "Could not create nightly build directories."
		exit 1
	fi
}

nightly_update()
{
	cd "${DEST_SOURCE}"
	if [ $? -ne 0 ]; then
		echo "Could not change into directory ${DEST_SOURCE}."
		exit 1
	fi

	if [ ! -e .git ]; then
		# initial clone of source
		heading "Cloning git repository..."
		"${GIT_BINARY}" clone "${GIT_ROOT}" .
		if [ $? -ne 0 ]; then
			echo "Failed to clone ${GIT_ROOT}."
			exit 1
		fi
	else
		# clean the updated source tree.
		heading "Cleaning git repository..."
		"${GIT_BINARY}" checkout . &&
		"${GIT_BINARY}" clean -dxf
		if [ $? -ne 0 ]; then
			echo "Failed to clean git repository."
			exit 1
		fi

		# update the source
		heading "Updating git repository..."
		"${GIT_BINARY}" pull
		if [ $? -ne 0 ]; then
			echo "Failed to pull from ${GIT_ROOT}."
			exit 1
		fi
	fi

	if [ ! -e "${LAST_BUILD_FILE}" ]; then
		echo "N/A" > "${LAST_BUILD_FILE}"
	fi

	LAST_BUILD_COMMIT="$(cat "${LAST_BUILD_FILE}")"
	CURRENT_COMMIT="$("${GIT_BINARY}" log --pretty="format:%H" HEAD...HEAD~1 | head -1)"

	if [ "${CURRENT_COMMIT}" = "${LAST_BUILD_COMMIT}" ]; then
		exit 2
	else
		heading "Changes detected."
		echo "Last built commit: ${LAST_BUILD_COMMIT}"
		echo "Current commit:    ${CURRENT_COMMIT}"
	fi
}

nightly_compile()
{
	heading "Compiling..."

	if [ ${CYGWIN} -eq 0 ]; then
		"${MAKE_PROGRAM}"
		if [ $? -ne 0 ]; then
			echo "${GIT_PROJECT} build failed."
			exit 1
		fi
	else
		(unset tmp; unset temp; cd VisualStudioNET && ./vs2010.bat devenv.com plc-utils-2010.sln /build)
		if [ $? -ne 0 ]; then
			echo "${GIT_PROJECT} build failed."
			exit 1
		fi
	fi
}

nightly_install()
{

	if [ ${CYGWIN} -eq 0 ]; then
		heading "Installing..."
		"${MAKE_PROGRAM}" BIN="${DEST_BINARY}" OWNER="$(id -u)" GROUP="$(id -g)" SUID_PERM="0555" install
		if [ $? -ne 0 ]; then
			echo "${GIT_PROJECT} install failed."
			exit 1
		fi
	fi

	# update last build file.
	echo -n "${CURRENT_COMMIT}" > "${LAST_BUILD_FILE}"
	if [ $? -ne 0 ]; then
		echo "Failed to update last build file."
		exit 1
	fi
}

nightly_build()
{
	nightly_update && nightly_compile && nightly_install
	return ${?}
}

nightly_report_start()
{
	rm -f "${NIGHTLY_LOG}"
	rm -f "${REPORT_FILE}"

	START_TIME="$(date +%s)"
}

nightly_report_end()
{
	END_TIME="$(date +%s)"
	ELAPSED_TIME="$((END_TIME - START_TIME)) seconds"
}

report_success()
{
	echo "Nightly build succeeded."
	echo
	echo "Build Host: $(uname -a)"
	echo "Elapsed time: ${ELAPSED_TIME}."

	if [ ${CYGWIN} -eq 0 ]; then
		echo "Install file count: $(find "${DEST_BINARY}" -type f | wc -l | tr -d ' 	')"
		echo "Install size: $(du -h "${DEST_BINARY}" | sed 's/\([^ 	]*\).*/\1/')"
	fi

	echo
	echo "Log:"
	echo
	cat "${NIGHTLY_LOG}"
}

report_failure()
{
	echo "Nightly build FAILED."
	echo
	echo "Build Host: $(uname -a)"
	echo "Elapsed time: ${ELAPSED_TIME}."
	echo
	echo "Log:"
	echo
	cat "${NIGHTLY_LOG}"
}

report_up2date()
{
	echo "No changes detected, skipping compile / install."
	echo
	echo "Build Host: $(uname -a)"
	echo "Elapsed time: ${ELAPSED_TIME}."
}

report_unknown()
{
	echo "Unknown error."
	echo
	echo "Build Host: $(uname -a)"
	echo "Elapsed time: ${ELAPSED_TIME}."
}

nightly_report()
{
	local BUILD_STATUS="$1"

	heading "Project: ${GIT_PROJECT}"

	case ${BUILD_STATUS} in
		0)
			report_success
			REPORT_STRING="Success"
			EMAIL_LIST="${SUCCESS_EMAIL_LIST}"
			;;
		1)
			report_failure
			REPORT_STRING="Failure"
			EMAIL_LIST="${FAILURE_EMAIL_LIST}"
			;;
		2)
			report_up2date
			REPORT_STRING="Up to Date"
			EMAIL_LIST="${NOCHANGE_EMAIL_LIST}"
			;;
		*)
			report_unknown
			REPORT_STRING="Unknown Error"
			EMAIL_LIST="${FAILURE_EMAIL_LIST}"
			;;
	esac
}

nightly_setup

nightly_report_start

(nightly_build) > "${NIGHTLY_LOG}" 2>&1
BUILD_STATUS="$?"

nightly_report_end

# generate nightly report
nightly_report ${BUILD_STATUS} > "${REPORT_FILE}" 2>&1

EMAIL_SUBJECT="[${GIT_PROJECT}] Nightly Build - ${REPORT_STRING}"

# email the report file.
if [ ${CYGWIN} -eq 0 ]; then
	mail -s "${EMAIL_SUBJECT}" ${EMAIL_LIST} < "${REPORT_FILE}"
else
(cat <<EOF
From: nightly_build@qca.qualcomm.com
To: ${EMAIL_LIST}
Subject: ${EMAIL_SUBJECT}

EOF
cat "${REPORT_FILE}") | /usr/sbin/ssmtp ${EMAIL_LIST}
fi

