import os
import yaml
from datetime import date
import uuid
from typing import Dict, List, Any


def _load_yaml_file(path: str) -> Dict[str, Any]:
    with open(path, "r") as f:
        data = yaml.safe_load(f)

        return data


def _normalize_sigma_rule_for_comparison(rule: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(rule)
    normalized.pop("id", None)
    normalized.pop("date", None)
    normalized.pop("modified", None)
    return normalized


def _sigma_rule_has_real_changes(filepath: str, new_rule: Dict[str, Any]) -> bool:
    if not os.path.exists(filepath):
        return True
    
    try:
        existing_rule = _load_yaml_file(filepath)
    except Exception as e:
        # If there's an error loading the existing rule, assume it must be changed to be safe
        print(f"Error loading existing Sigma rule from {filepath}: {e}\nAssuming changes are needed.")
        return True
    return _normalize_sigma_rule_for_comparison(existing_rule) != _normalize_sigma_rule_for_comparison(new_rule)


def extract_artifacts(yaml_data: Dict[str, Any]) -> Dict[str, List[str]]:
    artifacts = {"files": [], "registry": [], "network": [], "processes": []}

    for item in yaml_data.get("Artifacts", {}).get("Disk", []) or []:
        if isinstance(item, dict) and "File" in item:
            artifacts["files"].append(item["File"])

    for item in yaml_data.get("Artifacts", {}).get("Registry", []) or []:
        if isinstance(item, dict) and "Path" in item:
            artifacts["registry"].append(item["Path"])

    for item in yaml_data.get("Artifacts", {}).get("Network", []) or []:
        if isinstance(item, dict):
            if "Domains" in item:
                if isinstance(item["Domains"], list):
                    artifacts["network"].extend(item["Domains"])
                elif isinstance(item["Domains"], str):
                    artifacts["network"].append(item["Domains"])

    details = yaml_data.get("Details", {})
    if isinstance(details, dict):
        artifacts["processes"] = [
            os.path.basename(item)
            for item in details.get("InstallationPaths", []) or []
            if isinstance(item, str) and item.lower().endswith(".exe")
        ]

    return artifacts


def write_sigma_rule(rule: Dict[str, Any], filepath: str) -> None:
    """Write a Sigma rule using PyYAML to guarantee valid escaping and structure."""
    with open(filepath, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            rule,
            f,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=True,
            width=4096,
        )


def generate_sigma_rules(yaml_file: str, output_dir: str) -> List[Dict[str, Any]]:
    data = _load_yaml_file(yaml_file)

    name = data.get("Name", "Unknown")
    artifacts = extract_artifacts(data)

    rule_templates = {
        "registry": {
            "title": f"Potential {name} RMM Tool Registry Activity",
            "logsource": {"product": "windows", "category": "registry_event"},
            "detection_key": "TargetObject|contains",
        },
        "network": {
            "title": f"Potential {name} RMM Tool Network Activity",
            "logsource": {"product": "windows", "category": "network_connection"},
            "detection_key": "DestinationHostname|endswith",
        },
        "files": {
            "title": f"Potential {name} RMM Tool File Activity",
            "logsource": {"product": "windows", "category": "file_event"},
            "detection_key": "TargetFilename|endswith",
        },
        "processes": {
            "title": f"Potential {name} RMM Tool Process Activity",
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection_key": "special",  # Handles both ParentImage and Image
        },
    }

    generated_rules = []
    for artifact_type, rule_template in rule_templates.items():
        if artifacts[artifact_type]:
            # Build detection based on artifact type
            if artifact_type == "processes":
                detection = {
                    "selection_parent": {
                        "ParentImage|endswith": artifacts[artifact_type].copy()
                    },
                    "selection_image": {
                        "Image|endswith": artifacts[artifact_type].copy()
                    },
                    "condition": "1 of selection_*",
                }
            else:
                detection = {
                    "selection": {
                        rule_template["detection_key"]: artifacts[artifact_type].copy()
                    },
                    "condition": "selection",
                }

            # Create rule with proper field order
            rule = {
                "title": rule_template["title"],
                "id": str(uuid.uuid4()),
                "status": "experimental",
                "description": f"Detects potential {artifact_type} activity of {name} RMM tool",
                "references": ["https://github.com/magicsword-io/LOLRMM"],
                "author": "LOLRMM Project",
                "date": date.today().strftime("%Y-%m-%d"),
                "tags": ["attack.execution", "attack.t1219"],
                "logsource": rule_template["logsource"],
                "detection": detection,
                "falsepositives": [f"Legitimate use of {name}"],
                "level": "medium",
            }

            safe_name = (
                name.lower().replace(" ", "_").replace("(", "_").replace(")", "_")
            )
            output_file = f"{safe_name}_{artifact_type}_sigma.yml"
            full_output_path = os.path.join(output_dir, output_file)

            if _sigma_rule_has_real_changes(full_output_path, rule):
                write_sigma_rule(rule, full_output_path)

            github_url = f"https://github.com/magicsword-io/LOLRMM/blob/main/detections/sigma/{output_file}"
            generated_rules.append(
                {
                    "Sigma": github_url,
                    "Description": f"Detects potential {artifact_type} activity of {name} RMM tool",
                }
            )

    return generated_rules


def update_yaml_with_sigma_rules(
    yaml_file: str, sigma_rules: List[Dict[str, Any]]
) -> None:
    data = _load_yaml_file(yaml_file)

    if "Detections" not in data:
        data["Detections"] = []

    original_detections = list(data["Detections"])

    # Remove existing generated rules
    data["Detections"] = [
        rule
        for rule in data["Detections"]
        if not rule.get("Sigma", "").startswith(
            "https://github.com/magicsword-io/LOLRMM/blob/main/detections/sigma/"
        )
    ]

    # Add new generated rules
    updated_detections = data["Detections"] + sigma_rules

    if updated_detections == original_detections:
        return

    data["Detections"] = updated_detections

    with open(yaml_file, "w", encoding="utf-8") as f:
        yaml.dump(data, f, sort_keys=False)


def main() -> None:
    yaml_dir = "yaml/"
    output_dir = "detections/sigma/"
    os.makedirs(output_dir, exist_ok=True)

    for filename in os.listdir(yaml_dir):
        if filename.endswith(".yaml") or filename.endswith(".yml"):
            yaml_file = os.path.join(yaml_dir, filename)
            sigma_rules = generate_sigma_rules(yaml_file, output_dir)
            update_yaml_with_sigma_rules(yaml_file, sigma_rules)

    print(
        f"[+] Sigma rule generation and YAML update complete. Files saved in {output_dir}"
    )


if __name__ == "__main__":
    main()
