import os
import json
import uuid
import logging
import shutil
from datetime import datetime
from threading import Lock


logger = logging.getLogger(__name__)


BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

CACHE_DIR = os.path.join(
    BASE_DIR,
    "pcapCache"
)

FEEDBACK_FILE = os.path.join(
    CACHE_DIR,
    "ai_feedback.json"
)

feedback_lock = Lock()

MAX_FEEDBACK = 5000


def _ensure_cache_dir():
    os.makedirs(
        CACHE_DIR,
        exist_ok=True
    )


def _load_feedback():

    _ensure_cache_dir()

    try:

        if not os.path.exists(FEEDBACK_FILE):
            return []

        with open(
            FEEDBACK_FILE,
            "r",
            encoding="utf-8"
        ) as fp:

            data = json.load(fp)

            if isinstance(data, list):
                return data

            logger.warning(
                "AI feedback file does not contain a list: %s",
                FEEDBACK_FILE
            )

    except json.JSONDecodeError as exc:

        logger.error(
            "AI feedback file is corrupted: %s",
            exc
        )

        backup_file = (
            FEEDBACK_FILE +
            ".corrupt-" +
            datetime.now().strftime(
                "%Y%m%d-%H%M%S"
            )
        )

        try:
            shutil.copy2(
                FEEDBACK_FILE,
                backup_file
            )
        except OSError:
            pass

    except OSError as exc:

        logger.error(
            "Unable to read AI feedback file: %s",
            exc
        )

    return []


def _save_feedback(feedback):
    _ensure_cache_dir()

    with open(
        FEEDBACK_FILE,
        "w",
        encoding="utf-8"
    ) as fp:

        json.dump(
            feedback,
            fp,
            indent=4
        )


def save_feedback(data):

    if not isinstance(data, dict):
        raise ValueError(
            "Feedback must be a JSON object."
        )

    feedback_type = str(
        data.get("feedback")
        or ""
    ).lower()

    if feedback_type not in (
        "correct",
        "incorrect"
    ):
        raise ValueError(
            "Feedback must be 'correct' or 'incorrect'."
        )

    analysis_type = str(
        data.get("analysisType") or ""
    ).strip().lower()

    if analysis_type not in (
        "packet",
        "device"
    ):
        raise ValueError(
            "analysisType must be 'packet' or 'device'."
        )

    if (
        feedback_type == "incorrect"
        and not (
            data.get("correctedRisk")
            or data.get("correctedCategory")
            or str(
                data.get("comment") or ""
            ).strip()
        )
    ):
        raise ValueError(
            "Incorrect feedback must include "
            "a corrected risk, corrected category, "
            "or a comment."
        )

    record = {
        "id": str(uuid.uuid4()),

        "timestamp":
            datetime.now().isoformat(),

        "feedback":
            feedback_type,

        "analysisType":
            analysis_type,

        "deviceId":
            data.get("deviceId"),

        "packetId":
            data.get("packetId"),

        "ip":
            data.get("ip"),

        "predictedRisk":
            data.get("predictedRisk"),

        "predictedScore":
            data.get("predictedScore"),

        "predictedCategory":
            data.get("predictedCategory"),

        "correctedRisk":
            data.get("correctedRisk"),

        "correctedCategory":
            data.get("correctedCategory"),

        "comment":
            str(data.get("comment") or "")
    }

    with feedback_lock:

        history = _load_feedback()

        history.append(record)

        if len(history) > MAX_FEEDBACK:
            history = history[-MAX_FEEDBACK:]

        _save_feedback(history)

    return record


def get_feedback():

    with feedback_lock:
        return _load_feedback()


def get_feedback_summary():

    with feedback_lock:

        feedback = _load_feedback()

        total = len(feedback)

        correct = sum(
            1
            for item in feedback
            if item.get("feedback") == "correct"
        )

        incorrect = sum(
            1
            for item in feedback
            if item.get("feedback") == "incorrect"
        )

        return {
            "total": total,
            "correct": correct,
            "incorrect": incorrect,
            "accuracy": round(
                correct * 100 / total,
                2
            ) if total else 0
        }


def get_learning_examples(
    limit=5,
    analysis_type=None
):

    feedback = get_feedback()

    if analysis_type:

        feedback = [
            item
            for item in feedback
            if item.get("analysisType") ==
               analysis_type
        ]

    return feedback[-limit:]