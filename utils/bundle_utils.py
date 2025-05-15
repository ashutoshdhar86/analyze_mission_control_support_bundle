import os
import yaml
import json
from pathlib import Path
from typing import Dict, List, Optional

def parse_yaml_file(file_path: Path) -> Optional[Dict]:
    """Parse a YAML file and return its contents as a dictionary."""
    try:
        with open(file_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error parsing YAML file {file_path}: {str(e)}")
        return None

def parse_json_file(file_path: Path) -> Optional[Dict]:
    """Parse a JSON file and return its contents as a dictionary."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error parsing JSON file {file_path}: {str(e)}")
        return None

def find_files_by_pattern(directory: Path, pattern: str) -> List[Path]:
    """Find all files matching a pattern in the given directory."""
    return list(directory.rglob(pattern))

def analyze_log_file(log_file: Path) -> Dict:
    """Analyze a log file for common patterns and issues."""
    analysis = {
        "error_count": 0,
        "warning_count": 0,
        "critical_errors": [],
        "warnings": []
    }
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if "ERROR" in line or "error" in line:
                    analysis["error_count"] += 1
                    if any(crit in line.lower() for crit in ["fatal", "critical", "crash"]):
                        analysis["critical_errors"].append(line)
                elif "WARN" in line or "warning" in line:
                    analysis["warning_count"] += 1
                    analysis["warnings"].append(line)
    except Exception as e:
        print(f"Error analyzing log file {log_file}: {str(e)}")
    
    return analysis

def get_kubernetes_resources(bundle_path: Path) -> Dict:
    """Extract and analyze Kubernetes resources from the support bundle."""
    k8s_path = bundle_path / "kubernetes"
    if not k8s_path.exists():
        return {}
        
    resources = {
        "pods": [],
        "deployments": [],
        "services": [],
        "configmaps": [],
        "secrets": []
    }
    
    # Look for common Kubernetes resource files
    for resource_type in resources.keys():
        resource_files = find_files_by_pattern(k8s_path, f"*{resource_type}*.yaml")
        for file in resource_files:
            data = parse_yaml_file(file)
            if data:
                resources[resource_type].append(data)
                
    return resources

def analyze_application_configs(bundle_path: Path) -> Dict:
    """Analyze application configuration files."""
    configs_path = bundle_path / "configs"
    if not configs_path.exists():
        return {}
        
    configs = {}
    
    # Look for common configuration files
    config_patterns = ["*.yaml", "*.yml", "*.json", "*.conf", "*.config"]
    for pattern in config_patterns:
        for file in find_files_by_pattern(configs_path, pattern):
            if file.suffix in ['.yaml', '.yml']:
                configs[file.name] = parse_yaml_file(file)
            elif file.suffix == '.json':
                configs[file.name] = parse_json_file(file)
            else:
                try:
                    with open(file, 'r') as f:
                        configs[file.name] = f.read()
                except Exception as e:
                    print(f"Error reading config file {file}: {str(e)}")
                    
    return configs 