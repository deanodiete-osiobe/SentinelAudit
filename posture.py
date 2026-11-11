"""Shared, privacy-filtered fleet report schema for desktop and agent hosts."""
import uuid
ENGINE_VERSION = "sentinel-integrated-2"
OBSERVATIONS = frozenset({"protection_on", "fully_encrypted", "min_password_length",
    "password_complexity", "target_min_length", "target_complexity", "domain_state", "private_state", "public_state"})

def build_posture_report(result, run_id=None):
    return {"schema_version":1,"run_id":str(uuid.UUID(run_id)) if run_id else str(uuid.uuid4()),
        "engine_version":ENGINE_VERSION,"generated_utc":result.generated_utc.isoformat(),
        "findings":[{"finding_id":f.finding_id,"name":f.name,"status":f.status.value,
            "risk_level":f.risk_level.value,"observations":{k:v for k,v in f.details.items()
            if k in OBSERVATIONS and (type(v) is bool or type(v) is int and 0<=v<=1024
                                     or type(v) is str and v in ("ON","OFF"))}}
            for f in result.findings]}
