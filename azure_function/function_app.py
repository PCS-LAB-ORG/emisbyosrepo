from __future__ import annotations
import logging
import azure.functions as func
from byob_core.collectors import azure_defender
from byob_core import normalizer, cortex_client, secrets

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = func.FunctionApp()


@app.function_name("ScheduledSync")
@app.schedule(schedule="0 0 */6 * * *", arg_name="timer", run_on_startup=False)
def timer_trigger(timer: func.TimerRequest) -> None:
    logger.info("Scheduled sync triggered")
    try:
        _run_pipeline(mode="scheduled", resource_id=None)
    except Exception as exc:
        logger.exception("ScheduledSync failed: %s", exc)


@app.function_name("EventDrivenSync")
@app.event_grid_trigger(arg_name="event")
def event_grid_trigger(event: func.EventGridEvent) -> None:
    try:
        data = event.get_json()
        resource_id = data.get("id") or data.get("resourceId")
        logger.info("Event-driven trigger, resource_id: %s", resource_id)
        _run_pipeline(mode="event", resource_id=resource_id)
    except Exception as exc:
        logger.exception("EventDrivenSync failed: %s", exc)


def _run_pipeline(mode: str, resource_id: str | None) -> None:
    creds = secrets.load_credentials()
    findings = azure_defender.collect(mode=mode, resource_id=resource_id)
    if not findings:
        logger.info("No findings collected")
        return
    batches = normalizer.normalize(findings, "azure_defender")
    results = cortex_client.submit_all(batches, creds)
    total_assets = sum(r.assets_count for r in results)
    total_vulns = sum(r.vulnerabilities_count for r in results)
    logger.info("Done: %d batches, %d assets, %d vulns", len(results), total_assets, total_vulns)
