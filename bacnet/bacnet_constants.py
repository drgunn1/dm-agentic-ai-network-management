"""
Copyright 2026 NXP
SPDX-License-Identifier: BSD-3-Clause

BACnet protocol constants (ANSI/ASHRAE 135, Annex J for BACnet/IP).
Used by the parser to decode BVLC / NPDU / APDU fields into readable names.
"""

# UDP ports 0xBAC0..0xBACF are reserved for BACnet/IP. 47808 is the default.
BACNET_DEFAULT_PORT = 47808
BACNET_PORT_RANGE = range(0xBAC0, 0xBAD0)

# ---------------------------------------------------------------------------
# BVLC (BACnet Virtual Link Control, Annex J)
# ---------------------------------------------------------------------------
BVLC_TYPE_BIP = 0x81

BVLC_FUNCTIONS = {
    0x00: 'BVLC-Result',
    0x01: 'Write-Broadcast-Distribution-Table',
    0x02: 'Read-Broadcast-Distribution-Table',
    0x03: 'Read-Broadcast-Distribution-Table-Ack',
    0x04: 'Forwarded-NPDU',
    0x05: 'Register-Foreign-Device',
    0x06: 'Read-Foreign-Device-Table',
    0x07: 'Read-Foreign-Device-Table-Ack',
    0x08: 'Delete-Foreign-Device-Table-Entry',
    0x09: 'Distribute-Broadcast-To-Network',
    0x0A: 'Original-Unicast-NPDU',
    0x0B: 'Original-Broadcast-NPDU',
    0x0C: 'Secure-BVLL',
}

BVLC_FORWARDED_NPDU = 0x04
BVLC_FUNCTIONS_WITH_NPDU = {0x04, 0x09, 0x0A, 0x0B}

BVLC_RESULT_CODES = {
    0x0000: 'Successful completion',
    0x0010: 'Write-Broadcast-Distribution-Table NAK',
    0x0020: 'Read-Broadcast-Distribution-Table NAK',
    0x0030: 'Register-Foreign-Device NAK',
    0x0040: 'Read-Foreign-Device-Table NAK',
    0x0050: 'Delete-Foreign-Device-Table-Entry NAK',
    0x0060: 'Distribute-Broadcast-To-Network NAK',
}

# ---------------------------------------------------------------------------
# NPDU (network layer, clause 6)
# ---------------------------------------------------------------------------
NETWORK_MESSAGES = {
    0x00: 'Who-Is-Router-To-Network',
    0x01: 'I-Am-Router-To-Network',
    0x02: 'I-Could-Be-Router-To-Network',
    0x03: 'Reject-Message-To-Network',
    0x04: 'Router-Busy-To-Network',
    0x05: 'Router-Available-To-Network',
    0x06: 'Initialize-Routing-Table',
    0x07: 'Initialize-Routing-Table-Ack',
    0x08: 'Establish-Connection-To-Network',
    0x09: 'Disconnect-Connection-To-Network',
    0x0A: 'Challenge-Request',
    0x0B: 'Security-Payload',
    0x0C: 'Security-Response',
    0x0D: 'Request-Key-Update',
    0x0E: 'Update-Key-Set',
    0x0F: 'Update-Distribution-Key',
    0x10: 'Request-Master-Key',
    0x11: 'Set-Master-Key',
    0x12: 'What-Is-Network-Number',
    0x13: 'Network-Number-Is',
}

NETWORK_REJECT_REASONS = {
    0: 'other',
    1: 'router not directly connected to DNET / no route',
    2: 'router busy',
    3: 'unknown network layer message type',
    4: 'message too long',
    5: 'security error',
    6: 'addressing error',
}

# ---------------------------------------------------------------------------
# APDU (application layer, clause 20/21)
# ---------------------------------------------------------------------------
PDU_TYPES = {
    0: 'Confirmed-Request',
    1: 'Unconfirmed-Request',
    2: 'SimpleACK',
    3: 'ComplexACK',
    4: 'SegmentACK',
    5: 'Error',
    6: 'Reject',
    7: 'Abort',
}

CONFIRMED_SERVICES = {
    0: 'acknowledgeAlarm',
    1: 'confirmedCOVNotification',
    2: 'confirmedEventNotification',
    3: 'getAlarmSummary',
    4: 'getEnrollmentSummary',
    5: 'subscribeCOV',
    6: 'atomicReadFile',
    7: 'atomicWriteFile',
    8: 'addListElement',
    9: 'removeListElement',
    10: 'createObject',
    11: 'deleteObject',
    12: 'readProperty',
    13: 'readPropertyConditional',
    14: 'readPropertyMultiple',
    15: 'writeProperty',
    16: 'writePropertyMultiple',
    17: 'deviceCommunicationControl',
    18: 'confirmedPrivateTransfer',
    19: 'confirmedTextMessage',
    20: 'reinitializeDevice',
    21: 'vtOpen',
    22: 'vtClose',
    23: 'vtData',
    24: 'authenticate',
    25: 'requestKey',
    26: 'readRange',
    27: 'lifeSafetyOperation',
    28: 'subscribeCOVProperty',
    29: 'getEventInformation',
    30: 'subscribeCOVPropertyMultiple',
    31: 'confirmedCOVNotificationMultiple',
    32: 'confirmedAuditNotification',
    33: 'auditLogQuery',
}

UNCONFIRMED_SERVICES = {
    0: 'i-Am',
    1: 'i-Have',
    2: 'unconfirmedCOVNotification',
    3: 'unconfirmedEventNotification',
    4: 'unconfirmedPrivateTransfer',
    5: 'unconfirmedTextMessage',
    6: 'timeSynchronization',
    7: 'who-Has',
    8: 'who-Is',
    9: 'utcTimeSynchronization',
    10: 'writeGroup',
    11: 'unconfirmedCOVNotificationMultiple',
    12: 'unconfirmedAuditNotification',
    13: 'who-Am-I',
    14: 'you-Are',
}

# Confirmed services
SVC_ATOMIC_READ_FILE = 6
SVC_ATOMIC_WRITE_FILE = 7
SVC_CREATE_OBJECT = 10
SVC_DELETE_OBJECT = 11
SVC_WRITE_PROPERTY = 15
SVC_WRITE_PROPERTY_MULTIPLE = 16
SVC_DEVICE_COMM_CONTROL = 17
SVC_REINITIALIZE_DEVICE = 20

# Unconfirmed services
SVC_I_AM = 0
SVC_I_HAVE = 1
SVC_TIME_SYNC = 6
SVC_WHO_HAS = 7
SVC_WHO_IS = 8
SVC_UTC_TIME_SYNC = 9

REJECT_REASONS = {
    0: 'other',
    1: 'buffer-overflow',
    2: 'inconsistent-parameters',
    3: 'invalid-parameter-data-type',
    4: 'invalid-tag',
    5: 'missing-required-parameter',
    6: 'parameter-out-of-range',
    7: 'too-many-arguments',
    8: 'undefined-enumeration',
    9: 'unrecognized-service',
}

ABORT_REASONS = {
    0: 'other',
    1: 'buffer-overflow',
    2: 'invalid-apdu-in-this-state',
    3: 'preempted-by-higher-priority-task',
    4: 'segmentation-not-supported',
    5: 'security-error',
    6: 'insufficient-security',
    7: 'window-size-out-of-range',
    8: 'application-exceeded-reply-time',
    9: 'out-of-resources',
    10: 'tsm-timeout',
    11: 'apdu-too-long',
}

# Abort reasons that point at segmentation / APDU size mismatches
SEGMENTATION_ABORT_REASONS = {1, 4, 7, 11}

ERROR_CLASSES = {
    0: 'device',
    1: 'object',
    2: 'property',
    3: 'resources',
    4: 'security',
    5: 'services',
    6: 'vt',
    7: 'communication',
}

ERROR_CODES = {
    0: 'other',
    2: 'configuration-in-progress',
    3: 'device-busy',
    5: 'file-access-denied',
    9: 'invalid-data-type',
    26: 'password-failure',
    27: 'read-access-denied',
    29: 'service-request-denied',
    30: 'timeout',
    31: 'unknown-object',
    32: 'unknown-property',
    37: 'value-out-of-range',
    40: 'write-access-denied',
    42: 'invalid-array-index',
    43: 'cov-subscription-failed',
    44: 'not-cov-property',
    45: 'optional-functionality-not-supported',
}

ERROR_CLASS_SECURITY = 4
ERROR_CODE_PASSWORD_FAILURE = 26
# Error codes that indicate an access-control decision (possible probing)
ACCESS_DENIED_ERROR_CODES = {5, 26, 27, 29, 40}
# Error codes that indicate an overloaded / unhealthy device
DEVICE_HEALTH_ERROR_CODES = {2, 3, 30}
# Error codes clients routinely trigger while probing optional properties
BENIGN_ERROR_CODES = {31, 32, 42}

DCC_ENABLE_DISABLE = {
    0: 'enable',
    1: 'disable',
    2: 'disable-initiation',
}

REINITIALIZE_STATES = {
    0: 'coldstart',
    1: 'warmstart',
    2: 'start-backup',
    3: 'end-backup',
    4: 'start-restore',
    5: 'end-restore',
    6: 'abort-restore',
    7: 'activate-changes',
}

# ReinitializeDevice states after which the device restarts (expect a short outage)
RESTARTING_REINIT_STATES = {0, 1, 5, 7}
# ReinitializeDevice states that make up a backup / restore procedure
BACKUP_RESTORE_STATES = {2, 3, 4, 5, 6}

SEGMENTATION_SUPPORT = {
    0: 'segmented-both',
    1: 'segmented-transmit',
    2: 'segmented-receive',
    3: 'no-segmentation',
}

# BACnet object types / instance limits
OBJECT_TYPE_DEVICE = 8
MAX_INSTANCE = 0x3FFFFF          # 4194303 is the wildcard instance
WILDCARD_INSTANCE = 0x3FFFFF

# ---------------------------------------------------------------------------
# MS/TP (clause 9)
# ---------------------------------------------------------------------------
MSTP_FRAME_TYPES = {
    0: 'Token',
    1: 'Poll-For-Master',
    2: 'Reply-To-Poll-For-Master',
    3: 'Test-Request',
    4: 'Test-Response',
    5: 'BACnet-Data-Expecting-Reply',
    6: 'BACnet-Data-Not-Expecting-Reply',
    7: 'Reply-Postponed',
}
MSTP_DATA_FRAMES = {5, 6}
MSTP_MAX_MASTER = 127
MSTP_BROADCAST = 255
