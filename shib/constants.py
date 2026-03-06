"""Constant values used across the shib package"""
from enum import IntEnum, StrEnum

class MaxDurationSeconds(IntEnum):
    """Enum for max duration seconds options for AWS sessions.
    
    AWS IAM will only allow a minimum of 3600 seconds when setting the max session duration for a role.
    However, when requesting temporary tokens, 900 seconds is the minimum duration that can be requested.
    """
    UPPER_LIMIT = 43200 # 12 hours, max duration limit for AWS sessions
    DEFAULT = 3600 # 1 hour, default duration for AWS sessions
    LOWER_LIMIT = 900 # 15 minutes, minimum duration for AWS sessions

class UpdateMaxDurationOptions(StrEnum):
    """Enum for options for whether to update max duration for AWS sessions.
    
    'none' means do not update max duration and use the max duration stored in the config file or default if not specified.
    'all' means update max duration for all roles regardless of whether there is a stored max duration in the config file.
    'new' means only update max duration for roles that do not have a stored max duration in the config file or have a stored
        max duration that is greater than the actual max duration limit for the IAM role.
    """
    NONE = 'none'
    ALL = 'all'
    NEW = 'new'