#!/bin/bash
# Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
#
# Copyright (c) 2015-2016 Brocade Communications Systems, Inc.
# All rights reserved
#
# SPDX-License-Identifier: GPL-2.0-only

test_parse ()
{
    cat > "${SHUNIT_TMPDIR}"/a.log <<EOF
Dec 23 08:17:01 localhost command[12345]: This is the first log entry
Jan 06 07:35:05 localhost command[12345]: This is a log entry
EOF

    cat > "${SHUNIT_TMPDIR}"/b.log <<EOF
Jan 06 17:35:05 localhost command[12345]: This is the last log entry
EOF

    cat > "${SHUNIT_TMPDIR}"/c.log <<EOF
Jan 06 07:35:04 localhost daemon[6789]: This is a log entry
EOF

    #
    # Normal order
    #
    touch -t 200201060800 "${SHUNIT_TMPDIR}"/a.log
    touch -t 200201060800 "${SHUNIT_TMPDIR}"/c.log
    touch -t 200201061800 "${SHUNIT_TMPDIR}"/b.log

    RESULT=$(show-log-parser --debug "${SHUNIT_TMPDIR}"/*.log 2>/dev/null | awk 'FNR==1')
    assertTrue "Wrong log entry in line 1: $RESULT" \
        "$(echo "$RESULT" | grep -q first ; echo $?)"
    RESULT=$(show-log-parser --debug "${SHUNIT_TMPDIR}"/*.log 2>/dev/null | awk 'FNR==2')
    assertTrue "Wrong log entry in line 2: $RESULT" \
        "$(echo "$RESULT" | grep -q daemon ; echo $?)"

    #
    # Now daemon and last are one year ahead
    #
    touch -t 200101060800 "${SHUNIT_TMPDIR}"/c.log
    touch -t 200101061800 "${SHUNIT_TMPDIR}"/b.log
    touch -t 200201060800 "${SHUNIT_TMPDIR}"/a.log

    RESULT=$(show-log-parser --debug "${SHUNIT_TMPDIR}"/*.log 2>/dev/null | awk 'FNR==1')
    assertTrue "Wrong log entry in line 1: $RESULT" \
        "$(echo "$RESULT" | grep -q daemon ; echo $?)"
    RESULT=$(show-log-parser --debug "${SHUNIT_TMPDIR}"/*.log 2>/dev/null | awk 'FNR==2')
    assertTrue "Wrong log entry in line 2: $RESULT" \
        "$(echo "$RESULT" | grep -q last ; echo $?)"
}


oneTimeSetUp ()
{
    local THIS_DIR
    THIS_DIR=$(cd "$(dirname "${0}")" && pwd -P)

    # make SUT visible
    PATH="${THIS_DIR}/../scripts/:${PATH}"
    export PATH

    # the implementation knows about unittest implementation
    if [ -z "${SHUNIT_TMPDIR}" ] ; then
        SHUNIT_TMPDIR=$(mktemp -d)
        if [ -n "${SHUNIT_TMPDIR}" ] ; then
            trap "rm -rf ${SHUNIT_TMPDIR}" EXIT
        fi
    fi
    export SHUNIT_TMPDIR
}

tearDown ()
{
    # clean-up after every test
    if [ -n "${SHUNIT_TMPDIR}" ] ; then
        rm -fr "${SHUNIT_TMPDIR}/*"
    fi
}

# load and run shUnit2
[ -n "${ZSH_VERSION:-}" ] && SHUNIT_PARENT=$0
. shunit2
