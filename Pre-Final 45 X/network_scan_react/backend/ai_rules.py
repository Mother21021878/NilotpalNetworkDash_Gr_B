import os
import json
import uuid
import shutil
import logging
from copy import deepcopy
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


RULES_FILE = os.path.join(
    CACHE_DIR,
    "ai_rules.json"
)


rules_lock = Lock()


DEFAULT_CONFIG = {
    "enabled": True,

    "temperature": 0.3,

    "custom_instructions": "",

    "rules": []
}


SUPPORTED_OPERATORS = (
    "eq",
    "neq",
    "contains",
    "not_contains",
    "gt",
    "gte",
    "lt",
    "lte",
    "in"
)


SUPPORTED_ANALYSIS_TYPES = (
    "packet",
    "device",
    "both"
)


SUPPORTED_ACTION_TYPES = (
    "set_risk",
    "set_category",
    "add_score",
    "set_score",
    "add_recommendation"
)


# ---------------------------------------------------------
# Cache / Configuration Helpers
# ---------------------------------------------------------

def _ensure_cache_dir():

    os.makedirs(
        CACHE_DIR,
        exist_ok=True
    )


def _load_config():

    _ensure_cache_dir()

    if not os.path.exists(RULES_FILE):

        config = deepcopy(
            DEFAULT_CONFIG
        )

        _save_config(config)

        return config

    try:

        with open(
            RULES_FILE,
            "r",
            encoding="utf-8"
        ) as fp:

            data = json.load(fp)

        if not isinstance(
            data,
            dict
        ):

            raise ValueError(
                "AI rules configuration must be an object."
            )

        config = deepcopy(
            DEFAULT_CONFIG
        )

        config.update(
            data
        )

        if not isinstance(
            config.get("rules"),
            list
        ):

            config["rules"] = []

        return config

    except (
        json.JSONDecodeError,
        OSError,
        ValueError
    ) as exc:

        logger.error(
            "AI rules configuration error: %s",
            exc
        )

        try:

            backup_file = (
                RULES_FILE +
                ".corrupt-" +
                datetime.now().strftime(
                    "%Y%m%d-%H%M%S"
                )
            )

            shutil.copy2(
                RULES_FILE,
                backup_file
            )

        except Exception:

            pass

        return deepcopy(
            DEFAULT_CONFIG
        )


def _save_config(config):

    _ensure_cache_dir()

    temp_file = (
        RULES_FILE +
        ".tmp"
    )

    with open(
        temp_file,
        "w",
        encoding="utf-8"
    ) as fp:

        json.dump(
            config,
            fp,
            indent=4
        )

        fp.flush()

        try:
            os.fsync(
                fp.fileno()
            )
        except OSError:
            pass

    os.replace(
        temp_file,
        RULES_FILE
    )


# ---------------------------------------------------------
# AI Configuration
# ---------------------------------------------------------

def get_ai_config():

    with rules_lock:

        return _load_config()


def update_ai_config(data):

    if not isinstance(
        data,
        dict
    ):

        raise ValueError(
            "AI configuration must be an object."
        )

    with rules_lock:

        config = _load_config()

        if "enabled" in data:

            if not isinstance(
                data["enabled"],
                bool
            ):

                raise ValueError(
                    "AI enabled value must be true or false."
                )

            config["enabled"] = data["enabled"]

        if "temperature" in data:

            try:

                temperature = float(
                    data["temperature"]
                )

            except (
                TypeError,
                ValueError
            ):

                raise ValueError(
                    "Temperature must be a number."
                )

            config["temperature"] = max(
                0.0,
                min(
                    1.0,
                    temperature
                )
            )

        if "custom_instructions" in data:

            config["custom_instructions"] = str(
                data.get(
                    "custom_instructions"
                ) or ""
            ).strip()

        _save_config(
            config
        )

        return config


# ---------------------------------------------------------
# Custom Rule Retrieval
# ---------------------------------------------------------

def get_custom_rules(
    analysis_type=None
):

    config = get_ai_config()

    rules = config.get(
        "rules",
        []
    )

    if analysis_type:

        rules = [
            rule
            for rule in rules
            if rule.get(
                "analysisType"
            )
            in (
                analysis_type,
                "both"
            )
        ]

    return rules


# ---------------------------------------------------------
# Rule Validation
# ---------------------------------------------------------

def _validate_rule_data(
    data,
    partial=False
):

    if not isinstance(
        data,
        dict
    ):

        raise ValueError(
            "Rule must be an object."
        )

    if not partial or "name" in data:

        name = str(
            data.get("name") or ""
        ).strip()

        if not name:

            raise ValueError(
                "Rule name is required."
            )

        if len(name) > 200:

            raise ValueError(
                "Rule name must not exceed 200 characters."
            )

    if not partial or "field" in data:

        field = str(
            data.get("field") or ""
        ).strip()

        if not field:

            raise ValueError(
                "Rule field is required."
            )

        if len(field) > 200:

            raise ValueError(
                "Rule field must not exceed 200 characters."
            )

    if not partial or "operator" in data:

        operator = str(
            data.get("operator") or ""
        ).strip()

        if operator not in SUPPORTED_OPERATORS:

            raise ValueError(
                "Unsupported rule operator."
            )

        value = data.get(
            "value"
        )

        if operator in (
            "gt",
            "gte",
            "lt",
            "lte"
        ):

            try:

                float(value)

            except (
                TypeError,
                ValueError
            ):

                raise ValueError(
                    "Numeric comparison requires a numeric value."
                )

        elif operator == "in":

            if not isinstance(
                value,
                list
            ):

                raise ValueError(
                    "The 'in' operator requires a list of values."
                )

            if not value:

                raise ValueError(
                    "The 'in' operator requires at least one value."
                )

    if not partial or "analysisType" in data:

        analysis_type = str(
            data.get(
                "analysisType"
            ) or "both"
        ).strip()

        if analysis_type not in SUPPORTED_ANALYSIS_TYPES:

            raise ValueError(
                "Invalid analysis type."
            )

    if "enabled" in data:

        if not isinstance(
            data["enabled"],
            bool
        ):

            raise ValueError(
                "Rule enabled value must be true or false."
            )

    if not partial or "action" in data:

        action = data.get(
            "action"
        )

        if not isinstance(
            action,
            dict
        ):

            raise ValueError(
                "Rule action is required."
            )

        action_type = str(
            action.get("type") or ""
        ).strip()

        if action_type not in SUPPORTED_ACTION_TYPES:

            raise ValueError(
                "Unsupported rule action."
            )

        action_value = action.get(
            "value"
        )

        if action_type == "set_risk":

            allowed_risk_levels = {
                "Low",
                "Medium",
                "High",
                "Critical"
            }

            if str(
                action_value
            ).strip() not in allowed_risk_levels:

                raise ValueError(
                    "set_risk value must be "
                    "Low, Medium, High, or Critical."
                )

        if action_type in (
            "set_risk",
            "set_category",
            "add_recommendation"
        ):

            if (
                action_value is None
                or
                not str(
                    action_value
                ).strip()
            ):

                raise ValueError(
                    "Action value is required."
                )

        elif action_type in (
            "add_score",
            "set_score"
        ):

            try:

                float(
                    action_value
                )

            except (
                TypeError,
                ValueError
            ):

                raise ValueError(
                    "Score action value must be numeric."
                )

    return True


# ---------------------------------------------------------
# Add Custom Rule
# ---------------------------------------------------------

def _normalize_rule_value(
    value,
    operator
):

    if operator == "in":

        if isinstance(
            value,
            list
        ):
            return value

        return [
            item.strip()
            for item in str(
                value or ""
            ).split(",")
            if item.strip()
        ]

    if operator in (
        "gt",
        "gte",
        "lt",
        "lte"
    ):

        try:

            number = float(
                value
            )

            if number.is_integer():
                return int(number)

            return number

        except (
            TypeError,
            ValueError
        ):

            return value

    if operator in (
        "eq",
        "neq"
    ):

        text = str(
            value or ""
        ).strip()

        try:

            number = float(
                text
            )

            if text:
                return (
                    int(number)
                    if number.is_integer()
                    else number
                )

        except (
            TypeError,
            ValueError
        ):

            pass

        return text

    return value

def add_custom_rule(data):

    _validate_rule_data(
        data,
        partial=False
    )

    name = str(
        data.get("name") or ""
    ).strip()

    field = str(
        data.get("field") or ""
    ).strip()

    operator = str(
        data.get("operator") or ""
    ).strip()

    analysis_type = str(
        data.get(
            "analysisType"
        ) or "both"
    ).strip()

    action = data.get(
        "action"
    )

    rule = {

        "id":
            str(
                uuid.uuid4()
            ),

        "name":
            name,

        "enabled":
            bool(
                data.get(
                    "enabled",
                    True
                )
            ),

        "analysisType":
            analysis_type,

        "field":
            field,

        "operator":
            operator,

        "value":
            _normalize_rule_value(
                data.get(
                    "value"
                ),
                operator
            ),

        "action":
            deepcopy(
                action
            )
    }

    with rules_lock:

        config = _load_config()

        config.setdefault(
            "rules",
            []
        )

        config["rules"].append(
            rule
        )

        _save_config(
            config
        )

        return rule


# ---------------------------------------------------------
# Update Custom Rule
# ---------------------------------------------------------

def update_custom_rule(
    rule_id,
    data
):

    if not isinstance(
        data,
        dict
    ):

        raise ValueError(
            "Rule update must be an object."
        )

    allowed_fields = {
        "name",
        "enabled",
        "analysisType",
        "field",
        "operator",
        "value",
        "action"
    }

    update_data = {
        key: value
        for key, value in data.items()
        if key in allowed_fields
    }

    if not update_data:

        raise ValueError(
            "No valid rule fields were supplied."
        )

    with rules_lock:

        config = _load_config()

        for rule in config.get(
            "rules",
            []
        ):

            if rule.get(
                "id"
            ) != rule_id:

                continue

            candidate = deepcopy(
                rule
            )

            candidate.update(
                update_data
            )

            _validate_rule_data(
                candidate,
                partial=False
            )

            candidate["name"] = str(
                candidate.get(
                    "name"
                ) or ""
            ).strip()

            candidate["field"] = str(
                candidate.get(
                    "field"
                ) or ""
            ).strip()

            candidate["operator"] = str(
                candidate.get(
                    "operator"
                ) or ""
            ).strip()

            candidate["value"] = (
                _normalize_rule_value(
                    candidate.get("value"),
                    candidate["operator"]
                )
            )

            candidate["analysisType"] = str(
                candidate.get(
                    "analysisType"
                ) or "both"
            ).strip()

            candidate["action"] = deepcopy(
                candidate.get(
                    "action"
                )
            )

            rule.clear()

            rule.update(
                candidate
            )

            _save_config(
                config
            )

            return rule

    return None


# ---------------------------------------------------------
# Delete Custom Rule
# ---------------------------------------------------------

def delete_custom_rule(
    rule_id
):

    with rules_lock:

        config = _load_config()

        original = len(
            config.get(
                "rules",
                []
            )
        )

        config["rules"] = [
            rule
            for rule in config.get(
                "rules",
                []
            )
            if rule.get(
                "id"
            ) != rule_id
        ]

        if len(
            config["rules"]
        ) == original:

            return False

        _save_config(
            config
        )

        return True


# ---------------------------------------------------------
# Field Lookup
# ---------------------------------------------------------

def _get_field(
    data,
    field
):

    if not isinstance(
        data,
        dict
    ):

        return None

    if not field:

        return None

    aliases = {

        "riskLevel": [
            "riskLevel",
            "risk_level"
        ],

        "riskScore": [
            "riskScore",
            "risk_score"
        ],

        "riskCategory": [
            "riskCategory",
            "category"
        ]
    }

    if field in aliases:

        for key in aliases[field]:

            if key in data:

                return data.get(
                    key
                )

        return None

    value = data

    for part in field.split("."):

        if not isinstance(
            value,
            dict
        ):

            return None

        value = value.get(
            part
        )

    return value


def _get_rule_value(
    source_data,
    analysis,
    field
):
    """
    Resolve a rule field from the generated AI analysis first
    and then from the original source data.

    Analysis is checked first so that later rules can use
    values modified by earlier custom rules.
    """

    actual = _get_field(
        analysis,
        field
    )

    if actual is not None:
        return actual

    return _get_field(
        source_data,
        field
    )


# ---------------------------------------------------------
# Value Conversion Helpers
# ---------------------------------------------------------

def _to_number(
    value
):

    try:

        number = float(
            value
        )

        return number

    except (
        TypeError,
        ValueError
    ):

        return None


def _normalize_scalar(
    value
):

    if isinstance(
        value,
        bool
    ):

        return value

    if isinstance(
        value,
        (int, float)
    ):

        return value

    if value is None:

        return None

    text = str(
        value
    ).strip()

    if not text:

        return ""

    number = _to_number(
        text
    )

    if number is not None:

        if number.is_integer():

            return int(
                number
            )

        return number

    return text.lower()


# ---------------------------------------------------------
# Rule Matching
# ---------------------------------------------------------

def _matches(
    actual,
    operator,
    expected
):

    if operator not in SUPPORTED_OPERATORS:

        return False

    if actual is None:

        if operator == "neq":

            normalized_expected = (
                _normalize_scalar(
                    expected
                )
            )

            return normalized_expected is not None

        if operator == "not_contains":

            return True

        return False

    # -----------------------------------------------------
    # Equality
    # -----------------------------------------------------

    if operator in (
        "eq",
        "neq"
    ):

        actual_normalized = (
            _normalize_scalar(
                actual
            )
        )

        expected_normalized = (
            _normalize_scalar(
                expected
            )
        )

        if operator == "eq":

            return (
                actual_normalized ==
                expected_normalized
            )

        return (
            actual_normalized !=
            expected_normalized
        )

    # -----------------------------------------------------
    # Contains
    # -----------------------------------------------------

    if operator == "contains":

        return (
            str(expected).strip().lower()
            in
            str(actual).strip().lower()
        )

    # -----------------------------------------------------
    # Not Contains
    # -----------------------------------------------------

    if operator == "not_contains":

        return (
            str(expected).strip().lower()
            not in
            str(actual).strip().lower()
        )

    # -----------------------------------------------------
    # Numeric Comparisons
    # -----------------------------------------------------

    if operator in (
        "gt",
        "gte",
        "lt",
        "lte"
    ):

        actual_number = _to_number(
            actual
        )

        expected_number = _to_number(
            expected
        )

        if (
            actual_number is None
            or
            expected_number is None
        ):

            return False

        if operator == "gt":

            return (
                actual_number >
                expected_number
            )

        if operator == "gte":

            return (
                actual_number >=
                expected_number
            )

        if operator == "lt":

            return (
                actual_number <
                expected_number
            )

        if operator == "lte":

            return (
                actual_number <=
                expected_number
            )

    # -----------------------------------------------------
    # IN
    # -----------------------------------------------------

    if operator == "in":

        if not isinstance(
            expected,
            list
        ):

            return False

        normalized_actual = (
            _normalize_scalar(
                actual
            )
        )

        normalized_values = [

            _normalize_scalar(
                item
            )

            for item in expected

        ]

        return (
            normalized_actual
            in
            normalized_values
        )

    return False


# ---------------------------------------------------------
# Score Helper
# ---------------------------------------------------------

def _get_current_score(
    analysis
):

    score = analysis.get(
        "risk_score"
    )

    if score is None:

        score = analysis.get(
            "riskScore"
        )

    try:

        return float(
            score
        )

    except (
        TypeError,
        ValueError
    ):

        return 0.0


def _risk_level_from_score(
    score
):

    score = float(score)

    if score >= 80:
        return "Critical"

    if score >= 60:
        return "High"

    if score >= 40:
        return "Medium"

    return "Low"

def _set_score(
    analysis,
    score
):

    score = max(
        0.0,
        min(
            100.0,
            float(score)
        )
    )

    if score.is_integer():

        score = int(
            score
        )

    analysis["risk_score"] = score

    analysis["riskScore"] = score

    risk_level = _risk_level_from_score(score)

    analysis["risk_level"] = risk_level

    analysis["riskLevel"] = risk_level


# ---------------------------------------------------------
# Apply Custom Rules
# ---------------------------------------------------------

def apply_custom_rules(
    analysis,
    source_data,
    analysis_type
):

    if not isinstance(
        analysis,
        dict
    ):
        return analysis

    config = get_ai_config()

    if not config.get(
        "enabled",
        True
    ):

        analysis[
            "customRulesApplied"
        ] = []

        return analysis

    rules = get_custom_rules(
        analysis_type
    )

    applied_rules = []

    # Rules are evaluated in stored order.
    # Later matching rules may override earlier actions.

    for rule in rules:

        # -------------------------------------------------
        # Skip disabled rules
        # -------------------------------------------------

        if not rule.get(
            "enabled",
            True
        ):

            continue

        # -------------------------------------------------
        # Resolve condition field
        #
        # First check generated analysis so later rules
        # can use values modified by earlier rules.
        # If not found, fall back to original source data.
        # -------------------------------------------------

        field = str(
            rule.get(
                "field",
                ""
            )
        ).strip()

        actual = _get_rule_value(
            source_data,
            analysis,
            field
        )

        # -------------------------------------------------
        # Evaluate condition
        # -------------------------------------------------

        if not _matches(
            actual,
            rule.get(
                "operator"
            ),
            rule.get(
                "value"
            )
        ):

            continue

        # -------------------------------------------------
        # Rule matched
        # -------------------------------------------------

        action = rule.get(
            "action",
            {}
        )

        if not isinstance(
            action,
            dict
        ):

            logger.warning(
                "Ignoring invalid action in AI rule %s.",
                rule.get("id")
            )

            continue

        action_type = action.get(
            "type"
        )

        value = action.get(
            "value"
        )

        action_applied = False

        # -------------------------------------------------
        # SET RISK
        #
        # Changes only the risk classification.
        # It does not modify the numeric risk score.
        #
        # Use add_score or set_score when the numeric
        # risk score must also be changed.
        # -------------------------------------------------

        if action_type == "set_risk":

            risk_value = str(
                value or ""
            ).strip()

            if risk_value:

                analysis["risk_level"] = (
                    risk_value
                )

                analysis["riskLevel"] = (
                    risk_value
                )

                action_applied = True

        # -------------------------------------------------
        # SET CATEGORY
        # -------------------------------------------------

        elif action_type == "set_category":

            category_value = str(
                value or ""
            ).strip()

            if category_value:

                analysis["category"] = (
                    category_value
                )

                analysis["riskCategory"] = (
                    category_value
                )

                action_applied = True

        # -------------------------------------------------
        # ADD SCORE
        # -------------------------------------------------

        elif action_type == "add_score":

            try:

                score_delta = float(
                    value
                )

                current_score = (
                    _get_current_score(
                        analysis
                    )
                )

                new_score = (
                    current_score +
                    score_delta
                )

                _set_score(
                    analysis,
                    new_score
                )

                action_applied = True

            except (
                TypeError,
                ValueError
            ):

                logger.warning(
                    "Invalid add_score value in AI rule %s: %r",
                    rule.get("id"),
                    value
                )

        # -------------------------------------------------
        # SET SCORE
        # -------------------------------------------------

        elif action_type == "set_score":

            try:

                score = float(
                    value
                )

                _set_score(
                    analysis,
                    score
                )

                action_applied = True

            except (
                TypeError,
                ValueError
            ):

                logger.warning(
                    "Invalid set_score value in AI rule %s: %r",
                    rule.get("id"),
                    value
                )

        # -------------------------------------------------
        # ADD RECOMMENDATION
        # -------------------------------------------------

        elif action_type == "add_recommendation":

            recommendation = str(
                value or ""
            ).strip()

            if recommendation:

                recommendations = (
                    analysis.setdefault(
                        "recommendations",
                        []
                    )
                )

                if not isinstance(
                    recommendations,
                    list
                ):

                    recommendations = []

                    analysis[
                        "recommendations"
                    ] = recommendations

                if recommendation not in (
                    recommendations
                ):

                    recommendations.append(
                        recommendation
                    )

                action_applied = True

        # -------------------------------------------------
        # Unsupported action
        # -------------------------------------------------

        else:

            logger.warning(
                "Unsupported action type '%s' in AI rule %s.",
                action_type,
                rule.get("id")
            )

        # -------------------------------------------------
        # Record successfully applied rule
        # -------------------------------------------------

        if action_applied:

            applied_rules.append({
                "id": rule.get("id"),
                "name": rule.get("name"),
                "field": field,
                "operator": rule.get("operator"),
                "expectedValue": deepcopy(rule.get("value")),
                "actualValue": deepcopy(actual),
                "action": deepcopy(action)
            })

    # -----------------------------------------------------
    # Explainability
    #
    # Always expose the property so frontend/backend
    # consumers have a predictable structure.
    # -----------------------------------------------------

    analysis[
        "customRulesApplied"
    ] = applied_rules

    return analysis