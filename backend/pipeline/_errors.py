"""Pipeline-level control-flow errors shared across scanner and skill modules."""


class ScanCancelled(Exception):
    """Raised inside scanners/skills when the operator cancels the scan.

    Propagating this (instead of treating it as a failure) lets the async
    job runner mark the job as 'cancelled' rather than 'failed'.
    """