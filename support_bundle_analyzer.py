#!/usr/bin/env python3

import os
import yaml
import json
import click
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint
from datetime import datetime

console = Console()

class SupportBundleAnalyzer:
    def __init__(self, bundle_path):
        self.bundle_path = Path(bundle_path)
        self.console = Console()
        self.issues = []
        self.down_pods = []
        
    def analyze(self):
        """Main analysis function"""
        if not self.bundle_path.exists():
            self.console.print(f"[red]Error: Support bundle not found at {self.bundle_path}[/red]")
            return False
            
        self.console.print(Panel.fit("Replicated Support Bundle Analyzer", style="bold blue"))
        
        # Analyze bundle structure
        self.analyze_bundle_structure()
        
        # Analyze version information
        self.analyze_version_info()
        
        # Analyze Mission Control release info
        self.analyze_mission_control_release()
        
        # Get namespaces with StatefulSet pods
        sts_namespaces = set()
        pods_dir = self.bundle_path / "cluster-resources" / "pods"
        if pods_dir.exists():
            for pod_file in pods_dir.glob("*.json"):
                try:
                    with open(pod_file, 'r') as f:
                        pod_data = json.load(f)
                        if 'items' in pod_data:
                            for pod in pod_data['items']:
                                name = pod['metadata']['name']
                                if 'sts' in name.lower():
                                    sts_namespaces.add(pod['metadata']['namespace'])
                except Exception:
                    continue
        
        # Analyze certificates in StatefulSet namespaces
        if sts_namespaces:
            self.analyze_certificates(sts_namespaces)
            self.analyze_secrets(sts_namespaces)
        
        # Analyze storage
        self.analyze_storage()
        
        # Analyze StatefulSet pods
        self.analyze_sts_pods()
        
        # Display findings
        self.display_findings()
        
        return True
        
    def add_issue(self, severity, component, message):
        """Add an issue to the findings"""
        self.issues.append({
            'severity': severity,
            'component': component,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
        
    def analyze_bundle_structure(self):
        """Analyze the structure of the support bundle"""
        self.console.print("\n[bold]Bundle Structure Analysis[/bold]")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Component", style="dim")
        table.add_column("Status", justify="right")
        
        # Check for common directories and files
        components = {
            "version.yaml": "Version Information",
            "cluster-info": "Cluster Information",
            "cluster-resources": "Kubernetes Resources",
            "kots": "KOTS Data",
            "replicated": "Replicated Data",
            "secrets": "Secrets Information",
            "execution-data": "Execution Data"
        }
        
        for component, description in components.items():
            path = self.bundle_path / component
            status = "✓" if path.exists() else "✗"
            table.add_row(description, status)
            if not path.exists():
                self.add_issue("warning", "Bundle Structure", f"Missing {description}")
            
        self.console.print(table)
        
    def analyze_version_info(self):
        """Analyze version information from the bundle"""
        version_file = self.bundle_path / "version.yaml"
        if not version_file.exists():
            self.console.print("[yellow]Warning: version.yaml not found[/yellow]")
            self.add_issue("error", "Version Info", "version.yaml file is missing")
            return
            
        try:
            with open(version_file, 'r') as f:
                version_data = yaml.safe_load(f)
                
            self.console.print("\n[bold]Version Information[/bold]")
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Component", style="dim")
            table.add_column("Version", justify="right")
            
            if 'apiVersion' in version_data:
                table.add_row("API Version", version_data['apiVersion'])
            if 'kind' in version_data:
                table.add_row("Kind", version_data['kind'])
            if 'spec' in version_data and 'versionNumber' in version_data['spec']:
                version = version_data['spec']['versionNumber']
                table.add_row("Version Number", version)
                
            self.console.print(table)
            
        except Exception as e:
            self.console.print(f"[red]Error reading version information: {str(e)}[/red]")
            self.add_issue("error", "Version Info", f"Error reading version information: {str(e)}")
            
    def analyze_mission_control_release(self):
        """Analyze Mission Control release information"""
        app_info_file = self.bundle_path / "replicated-app-info.json"
        if not app_info_file.exists():
            self.console.print("[yellow]Warning: replicated-app-info.json not found[/yellow]")
            self.add_issue("error", "Mission Control", "replicated-app-info.json is missing")
            return
            
        try:
            with open(app_info_file, 'r') as f:
                app_data = json.load(f)
                
            if 'response' in app_data and 'raw_json' in app_data['response']:
                release_info = app_data['response']['raw_json']
                
                self.console.print("\n[bold]Mission Control Release Information[/bold]")
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Component", style="dim")
                table.add_column("Value", justify="right")
                
                if 'appName' in release_info:
                    table.add_row("Application", release_info['appName'])
                if 'appStatus' in release_info:
                    status = release_info['appStatus']
                    status_color = "green" if status == "ready" else "yellow"
                    table.add_row("Status", f"[{status_color}]{status}[/{status_color}]")
                
                if 'currentRelease' in release_info:
                    release = release_info['currentRelease']
                    if 'versionLabel' in release:
                        table.add_row("Version", release['versionLabel'])
                    if 'releaseNotes' in release:
                        table.add_row("Release Notes", release['releaseNotes'])
                    if 'deployedAt' in release:
                        table.add_row("Deployed At", release['deployedAt'])
                    if 'helmReleaseRevision' in release:
                        table.add_row("Helm Revision", str(release['helmReleaseRevision']))
                
                self.console.print(table)
                
        except Exception as e:
            self.console.print(f"[red]Error reading Mission Control release information: {str(e)}[/red]")
            self.add_issue("error", "Mission Control", f"Error reading release information: {str(e)}")
            
    def check_cert_expiration(self, cert_path):
        """Check certificate expiration date"""
        try:
            import subprocess
            result = subprocess.run(['openssl', 'x509', '-in', cert_path, '-noout', '-enddate'], 
                                 capture_output=True, text=True)
            if result.returncode == 0:
                # Extract date from output like "notAfter=Jan 1 00:00:00 2025 GMT"
                date_str = result.stdout.strip().split('=')[1]
                return date_str
            return "Unable to read certificate"
        except Exception as e:
            return f"Error reading certificate: {str(e)}"

    def analyze_certificates(self, namespaces):
        """Analyze certificates in specified namespaces"""
        self.console.print("\n[bold]Certificate Analysis[/bold]")
        
        certs_dir = self.bundle_path / "cluster-resources" / "custom-resources"
        if not certs_dir.exists():
            self.console.print("[yellow]Warning: custom-resources directory not found[/yellow]")
            self.add_issue("error", "Certificates", "custom-resources directory is missing")
            return
            
        # Create table for certificates
        cert_table = Table(show_header=True, header_style="bold magenta")
        cert_table.add_column("Namespace", style="dim")
        cert_table.add_column("Certificate Name", style="dim")
        cert_table.add_column("Status", justify="right")
        cert_table.add_column("Expiration Date", style="dim")
        cert_table.add_column("Issuer", style="dim")
        cert_table.add_column("Secret Name", style="dim")
        
        try:
            for namespace in namespaces:
                cert_file = certs_dir / f"{namespace}.json"
                if cert_file.exists():
                    with open(cert_file, 'r') as f:
                        cert_data = json.load(f)
                        if 'items' in cert_data:
                            for item in cert_data['items']:
                                if item.get('kind') == 'Certificate':
                                    cert_name = item['metadata']['name']
                                    status = item.get('status', {})
                                    
                                    # Get certificate status
                                    cert_status = "Unknown"
                                    if 'conditions' in status:
                                        for condition in status['conditions']:
                                            if condition.get('type') == 'Ready':
                                                cert_status = "Ready" if condition.get('status') == 'True' else "Not Ready"
                                    
                                    # Get expiration date
                                    expiration = "Unknown"
                                    if 'notAfter' in status:
                                        expiration = status['notAfter']
                                    
                                    # Get issuer
                                    issuer = item.get('spec', {}).get('issuerRef', {}).get('name', 'Unknown')
                                    
                                    # Get secret name
                                    secret_name = item.get('spec', {}).get('secretName', 'Unknown')
                                    
                                    # Add row to table
                                    status_color = "green" if cert_status == "Ready" else "yellow"
                                    cert_table.add_row(
                                        namespace,
                                        cert_name,
                                        f"[{status_color}]{cert_status}[/{status_color}]",
                                        expiration,
                                        issuer,
                                        secret_name
                                    )
                                    
                                    # Add issue if certificate is not ready
                                    if cert_status != "Ready":
                                        self.add_issue("warning", "Certificates", 
                                            f"Certificate {cert_name} in namespace {namespace} is not ready")
                                    
                                    # Add issue if certificate is close to expiration (within 30 days)
                                    if expiration != "Unknown":
                                        try:
                                            exp_date = datetime.strptime(expiration, "%Y-%m-%dT%H:%M:%SZ")
                                            days_until_exp = (exp_date - datetime.now()).days
                                            if days_until_exp <= 30:
                                                self.add_issue("warning", "Certificates",
                                                    f"Certificate {cert_name} in namespace {namespace} expires in {days_until_exp} days")
                                        except ValueError:
                                            pass
            
            if cert_table.row_count > 0:
                self.console.print(cert_table)
            else:
                self.console.print("[yellow]No certificates found in the specified namespaces[/yellow]")
                
        except Exception as e:
            self.console.print(f"[red]Error analyzing certificates: {str(e)}[/red]")
            self.add_issue("error", "Certificates", f"Error analyzing certificates: {str(e)}")

    def analyze_secrets(self, namespaces):
        """Analyze secrets in specified namespaces"""
        self.console.print("\n[bold]Secret Analysis[/bold]")
        
        secrets_dir = self.bundle_path / "secrets"
        if not secrets_dir.exists():
            self.console.print("[yellow]Warning: secrets directory not found[/yellow]")
            self.add_issue("error", "Secrets", "secrets directory is missing")
            return
            
        # Create table for secrets
        secret_table = Table(show_header=True, header_style="bold magenta")
        secret_table.add_column("Namespace", style="dim")
        secret_table.add_column("Secret Name", style="dim")
        secret_table.add_column("Type", style="dim")
        secret_table.add_column("Status", justify="right")
        
        try:
            for namespace in namespaces:
                namespace_dir = secrets_dir / namespace
                if namespace_dir.exists():
                    for secret_dir in namespace_dir.iterdir():
                        if secret_dir.is_dir():
                            secret_name = secret_dir.name
                            # Check if this is a TLS secret
                            is_tls = False
                            if (secret_dir / "tls.crt").exists() or (secret_dir / "tls.key").exists():
                                is_tls = True
                            
                            secret_type = "TLS" if is_tls else "Opaque"
                            status = "Present" if secret_dir.exists() else "Missing"
                            
                            # Add row to table
                            secret_table.add_row(
                                namespace,
                                secret_name,
                                secret_type,
                                f"[green]{status}[/green]"
                            )
                            
                            # Add warning if secret is missing
                            if status == "Missing":
                                self.add_issue("warning", "Secrets", 
                                    f"Secret {secret_name} in namespace {namespace} is missing")
            
            if secret_table.row_count > 0:
                self.console.print(secret_table)
                self.console.print("\n[yellow]Note: Secret contents are not included in the support bundle for security reasons.[/yellow]")
                self.console.print("[yellow]To check certificate expiration dates, please use the certificate analysis section.[/yellow]")
            else:
                self.console.print("[yellow]No secrets found in the specified namespaces[/yellow]")
                
        except Exception as e:
            self.console.print(f"[red]Error analyzing secrets: {str(e)}[/red]")
            self.add_issue("error", "Secrets", f"Error analyzing secrets: {str(e)}")

    def analyze_storage(self):
        """Analyze PersistentVolumes and PersistentVolumeClaims"""
        self.console.print("\n[bold]Storage Analysis[/bold]")
        
        # Analyze PVs
        pvs_file = self.bundle_path / "cluster-resources" / "pvs.json"
        if not pvs_file.exists():
            self.console.print("[yellow]Warning: pvs.json not found[/yellow]")
            self.add_issue("error", "Storage", "pvs.json file is missing")
        else:
            try:
                with open(pvs_file, 'r') as f:
                    pvs_data = json.load(f)
                    
                # Create table for PVs
                pv_table = Table(show_header=True, header_style="bold magenta")
                pv_table.add_column("PV Name", style="dim")
                pv_table.add_column("Status", justify="right")
                pv_table.add_column("Claim", style="dim")
                pv_table.add_column("Storage Class", style="dim")
                pv_table.add_column("Capacity", style="dim")
                pv_table.add_column("Reason", style="dim")
                
                if 'items' in pvs_data:
                    for pv in pvs_data['items']:
                        name = pv['metadata']['name']
                        status = pv.get('status', {}).get('phase', 'Unknown')
                        claim_ref = pv.get('spec', {}).get('claimRef', {})
                        claim = f"{claim_ref.get('namespace', '')}/{claim_ref.get('name', '')}" if claim_ref else "None"
                        storage_class = pv.get('spec', {}).get('storageClassName', 'None')
                        capacity = pv.get('spec', {}).get('capacity', {}).get('storage', 'Unknown')
                        
                        # Check for terminating state
                        is_terminating = pv.get('metadata', {}).get('deletionTimestamp') is not None
                        reason = "Terminating" if is_terminating else "N/A"
                        
                        # Add row to table
                        status_color = "green" if status == "Bound" else "yellow" if status == "Available" else "red"
                        pv_table.add_row(
                            name,
                            f"[{status_color}]{status}[/{status_color}]",
                            claim,
                            storage_class,
                            capacity,
                            reason
                        )
                        
                        # Add issues for problematic PVs
                        if is_terminating:
                            self.add_issue("warning", "Storage", f"PV {name} is terminating")
                        elif status not in ["Bound", "Available"]:
                            self.add_issue("warning", "Storage", f"PV {name} is in {status} state")
                
                if pv_table.row_count > 0:
                    self.console.print("\n[bold]PersistentVolumes[/bold]")
                    self.console.print(pv_table)
                else:
                    self.console.print("[yellow]No PersistentVolumes found[/yellow]")
                    
            except Exception as e:
                self.console.print(f"[red]Error analyzing PVs: {str(e)}[/red]")
                self.add_issue("error", "Storage", f"Error analyzing PVs: {str(e)}")
        
        # Analyze PVCs
        pvcs_dir = self.bundle_path / "cluster-resources" / "pvcs"
        if not pvcs_dir.exists():
            self.console.print("[yellow]Warning: pvcs directory not found[/yellow]")
            self.add_issue("error", "Storage", "pvcs directory is missing")
        else:
            try:
                # Create table for PVCs
                pvc_table = Table(show_header=True, header_style="bold magenta")
                pvc_table.add_column("Namespace", style="dim")
                pvc_table.add_column("PVC Name", style="dim")
                pvc_table.add_column("Status", justify="right")
                pvc_table.add_column("Volume", style="dim")
                pvc_table.add_column("Storage Class", style="dim")
                pvc_table.add_column("Capacity", style="dim")
                pvc_table.add_column("Reason", style="dim")
                
                for pvc_file in pvcs_dir.glob("*.json"):
                    with open(pvc_file, 'r') as f:
                        pvc_data = json.load(f)
                        if 'items' in pvc_data:
                            for pvc in pvc_data['items']:
                                namespace = pvc['metadata']['namespace']
                                name = pvc['metadata']['name']
                                status = pvc.get('status', {}).get('phase', 'Unknown')
                                volume_name = pvc.get('spec', {}).get('volumeName', 'None')
                                storage_class = pvc.get('spec', {}).get('storageClassName', 'None')
                                capacity = pvc.get('status', {}).get('capacity', {}).get('storage', 'Unknown')
                                
                                # Check for terminating state
                                is_terminating = pvc.get('metadata', {}).get('deletionTimestamp') is not None
                                reason = "Terminating" if is_terminating else "N/A"
                                
                                # Add row to table
                                status_color = "green" if status == "Bound" else "red"
                                pvc_table.add_row(
                                    namespace,
                                    name,
                                    f"[{status_color}]{status}[/{status_color}]",
                                    volume_name,
                                    storage_class,
                                    capacity,
                                    reason
                                )
                                
                                # Add issues for problematic PVCs
                                if is_terminating:
                                    self.add_issue("warning", "Storage", f"PVC {name} in namespace {namespace} is terminating")
                                elif status != "Bound":
                                    self.add_issue("warning", "Storage", f"PVC {name} in namespace {namespace} is not bound")
                
                if pvc_table.row_count > 0:
                    self.console.print("\n[bold]PersistentVolumeClaims[/bold]")
                    self.console.print(pvc_table)
                else:
                    self.console.print("[yellow]No PersistentVolumeClaims found[/yellow]")
                    
            except Exception as e:
                self.console.print(f"[red]Error analyzing PVCs: {str(e)}[/red]")
                self.add_issue("error", "Storage", f"Error analyzing PVCs: {str(e)}")

    def analyze_sts_pods(self):
        """Analyze StatefulSet pods"""
        self.console.print("\n[bold]StatefulSet Pods Analysis[/bold]")
        
        pods_dir = self.bundle_path / "cluster-resources" / "pods"
        events_dir = self.bundle_path / "cluster-resources" / "events"
        
        if not pods_dir.exists():
            self.console.print("[yellow]Warning: pods directory not found[/yellow]")
            self.add_issue("error", "StatefulSet Pods", "pods directory is missing")
            return
            
        # Create tables for different pod states
        running_table = Table(show_header=True, header_style="bold magenta")
        running_table.add_column("Namespace", style="dim")
        running_table.add_column("Pod Name", style="dim")
        running_table.add_column("StatefulSet", style="dim")
        running_table.add_column("Pod Ready", justify="right")
        running_table.add_column("Containers", style="dim")
        running_table.add_column("Readiness Details", style="dim")
        
        error_table = Table(show_header=True, header_style="bold magenta")
        error_table.add_column("Namespace", style="dim")
        error_table.add_column("Pod Name", style="dim")
        error_table.add_column("StatefulSet", style="dim")
        error_table.add_column("Status", justify="right")
        error_table.add_column("Container", style="dim")
        error_table.add_column("State", style="dim")
        error_table.add_column("Reason", style="dim")
        error_table.add_column("Message", style="dim")
        
        # Load events for readiness probe failures
        readiness_events = {}
        if events_dir.exists():
            for event_file in events_dir.glob("*.json"):
                try:
                    with open(event_file, 'r') as f:
                        event_data = json.load(f)
                        if 'items' in event_data:
                            for event in event_data['items']:
                                if event.get('reason') == 'Unhealthy' and 'Readiness probe failed' in event.get('message', ''):
                                    namespace = event.get('involvedObject', {}).get('namespace')
                                    pod_name = event.get('involvedObject', {}).get('name')
                                    if namespace and pod_name:
                                        key = f"{namespace}/{pod_name}"
                                        readiness_events[key] = {
                                            'message': event.get('message', ''),
                                            'last_timestamp': event.get('lastTimestamp', ''),
                                            'count': event.get('count', 0)
                                        }
                except Exception as e:
                    self.console.print(f"[red]Error reading events file {event_file}: {str(e)}[/red]")
        
        try:
            for pod_file in pods_dir.glob("*.json"):
                with open(pod_file, 'r') as f:
                    pod_data = json.load(f)
                    if 'items' in pod_data:
                        for pod in pod_data['items']:
                            name = pod['metadata']['name']
                            # Check if pod name contains 'sts'
                            if 'sts' in name.lower():
                                namespace = pod['metadata']['namespace']
                                status = pod.get('status', {})
                                phase = status.get('phase', 'Unknown')
                                
                                # Extract StatefulSet name from pod name
                                sts_name = name.rsplit('-', 1)[0]  # Remove the ordinal number
                                
                                # Get container statuses
                                container_statuses = status.get('containerStatuses', [])
                                init_container_statuses = status.get('initContainerStatuses', [])
                                
                                # Check pod readiness
                                conditions = status.get('conditions', [])
                                pod_ready = False
                                readiness_message = []
                                
                                for condition in conditions:
                                    if condition.get('type') == 'Ready':
                                        pod_ready = condition.get('status') == 'True'
                                        if not pod_ready:
                                            readiness_message.append(f"Pod not ready: {condition.get('message', 'No message')}")
                                
                                # Check for readiness probe failures in events
                                event_key = f"{namespace}/{name}"
                                if event_key in readiness_events:
                                    event = readiness_events[event_key]
                                    readiness_message.append(
                                        f"Readiness probe failed: {event['message']} "
                                        f"(Last seen: {event['last_timestamp']}, Count: {event['count']})"
                                    )
                                
                                # Get readiness probe configuration
                                for container in pod.get('spec', {}).get('containers', []):
                                    container_name = container.get('name', 'Unknown')
                                    probe = container.get('readinessProbe', {})
                                    if probe:
                                        probe_type = None
                                        probe_details = []
                                        
                                        if 'httpGet' in probe:
                                            http_get = probe['httpGet']
                                            probe_type = "HTTP GET"
                                            probe_details.extend([
                                                f"Path: {http_get.get('path', '/')}",
                                                f"Port: {http_get.get('port', 'Unknown')}",
                                                f"Scheme: {http_get.get('scheme', 'HTTP')}"
                                            ])
                                        elif 'tcpSocket' in probe:
                                            tcp = probe['tcpSocket']
                                            probe_type = "TCP Socket"
                                            probe_details.append(f"Port: {tcp.get('port', 'Unknown')}")
                                        elif 'exec' in probe:
                                            exec_cmd = probe['exec']
                                            probe_type = "Exec"
                                            probe_details.append(f"Command: {' '.join(exec_cmd.get('command', []))}")
                                            
                                            # Check for certificate expiration if the command involves certificates
                                            if '--cert' in exec_cmd.get('command', []):
                                                cert_paths = []
                                                for i, arg in enumerate(exec_cmd.get('command', [])):
                                                    if arg in ['--cert', '--key', '--cacert'] and i + 1 < len(exec_cmd.get('command', [])):
                                                        cert_paths.append(exec_cmd['command'][i + 1])
                                                
                                                if cert_paths:
                                                    probe_details.append("\nCertificate Expiration Dates:")
                                                    for cert_path in cert_paths:
                                                        expiration = self.check_cert_expiration(cert_path)
                                                        probe_details.append(f"  {cert_path}: {expiration}")
                                        
                                        if probe_type:
                                            probe_details.extend([
                                                f"Initial Delay: {probe.get('initialDelaySeconds', 0)}s",
                                                f"Period: {probe.get('periodSeconds', 10)}s",
                                                f"Timeout: {probe.get('timeoutSeconds', 1)}s",
                                                f"Success Threshold: {probe.get('successThreshold', 1)}",
                                                f"Failure Threshold: {probe.get('failureThreshold', 3)}"
                                            ])
                                            
                                            readiness_message.append(
                                                f"\n{container_name} Readiness Probe ({probe_type}):\n" +
                                                "\n".join(f"  {detail}" for detail in probe_details)
                                            )
                                
                                # Check for failed or error states
                                has_errors = False
                                container_errors = []
                                
                                # Check init containers first
                                for container in init_container_statuses:
                                    container_name = container.get('name', 'Unknown')
                                    state = container.get('state', {})
                                    
                                    if 'waiting' in state:
                                        has_errors = True
                                        container_errors.append({
                                            'name': container_name,
                                            'state': 'Waiting',
                                            'reason': state['waiting'].get('reason', 'Unknown'),
                                            'message': state['waiting'].get('message', 'Unknown')
                                        })
                                    elif 'terminated' in state and state['terminated'].get('exitCode', 0) != 0:
                                        has_errors = True
                                        container_errors.append({
                                            'name': container_name,
                                            'state': 'Terminated',
                                            'reason': state['terminated'].get('reason', 'Unknown'),
                                            'message': state['terminated'].get('message', 'Unknown')
                                        })
                                
                                # Check regular containers
                                for container in container_statuses:
                                    container_name = container.get('name', 'Unknown')
                                    state = container.get('state', {})
                                    ready = container.get('ready', False)
                                    
                                    if not ready:
                                        readiness_message.append(f"{container_name}: Not ready")
                                    
                                    if 'waiting' in state:
                                        has_errors = True
                                        container_errors.append({
                                            'name': container_name,
                                            'state': 'Waiting',
                                            'reason': state['waiting'].get('reason', 'Unknown'),
                                            'message': state['waiting'].get('message', 'Unknown')
                                        })
                                    elif 'terminated' in state and state['terminated'].get('exitCode', 0) != 0:
                                        has_errors = True
                                        container_errors.append({
                                            'name': container_name,
                                            'state': 'Terminated',
                                            'reason': state['terminated'].get('reason', 'Unknown'),
                                            'message': state['terminated'].get('message', 'Unknown')
                                        })
                                
                                if has_errors or phase in ['Failed', 'Error']:
                                    # Add pod-level error if no specific container errors
                                    if not container_errors:
                                        error_table.add_row(
                                            namespace,
                                            name,
                                            sts_name,
                                            f"[red]{phase}[/red]",
                                            "N/A",
                                            "N/A",
                                            "Pod Error",
                                            "No specific container errors found"
                                        )
                                        self.add_issue("error", "StatefulSet Pods", f"Pod {name} in namespace {namespace} is {phase}")
                                    
                                    # Add container-level errors
                                    for error in container_errors:
                                        error_table.add_row(
                                            namespace,
                                            name,
                                            sts_name,
                                            f"[red]{phase}[/red]",
                                            error['name'],
                                            error['state'],
                                            error['reason'],
                                            error['message']
                                        )
                                        self.add_issue("error", "StatefulSet Pods", 
                                            f"Container {error['name']} in pod {name} ({namespace}) is {error['state']}: {error['reason']} - {error['message']}")
                                else:
                                    # Show container status for running pods
                                    container_status = []
                                    for container in container_statuses:
                                        container_name = container.get('name', 'Unknown')
                                        ready = container.get('ready', False)
                                        status_color = "green" if ready else "yellow"
                                        container_status.append(f"[{status_color}]{container_name}[/{status_color}]")
                                    
                                    # Add readiness status
                                    pod_ready_status = "[green]Ready[/green]" if pod_ready else "[yellow]Not Ready[/yellow]"
                                    if not pod_ready:
                                        self.add_issue("warning", "StatefulSet Pods", 
                                            f"Pod {name} in namespace {namespace} is not ready: {', '.join(readiness_message)}")
                                    
                                    running_table.add_row(
                                        namespace,
                                        name,
                                        sts_name,
                                        pod_ready_status,
                                        ", ".join(container_status),
                                        "\n".join(readiness_message) if readiness_message else "All containers ready"
                                    )
            
            # Display running pods first
            if running_table.row_count > 0:
                self.console.print("\n[bold]Running StatefulSet Pods[/bold]")
                self.console.print(running_table)
            
            # Display pods with errors
            if error_table.row_count > 0:
                self.console.print("\n[bold]StatefulSet Pods with Issues[/bold]")
                self.console.print(error_table)
                
            if running_table.row_count == 0 and error_table.row_count == 0:
                self.console.print("[yellow]No StatefulSet pods found[/yellow]")
                self.add_issue("warning", "StatefulSet Pods", "No StatefulSet pods found")
            
        except Exception as e:
            self.console.print(f"[red]Error analyzing StatefulSet pods: {str(e)}[/red]")
            self.add_issue("error", "StatefulSet Pods", f"Error analyzing StatefulSet pods: {str(e)}")
            
    def display_findings(self):
        """Display all findings and issues"""
        if not self.issues:
            self.console.print("\n[green]No issues found in the support bundle.[/green]")
            return
            
        self.console.print("\n[bold]Findings and Issues[/bold]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="dim")
        table.add_column("Component", style="dim")
        table.add_column("Message", style="dim")
        
        # Sort issues by severity (error > warning)
        severity_order = {"error": 0, "warning": 1}
        sorted_issues = sorted(self.issues, key=lambda x: severity_order[x['severity']])
        
        for issue in sorted_issues:
            severity_color = "red" if issue['severity'] == "error" else "yellow"
            table.add_row(
                f"[{severity_color}]{issue['severity'].upper()}[/{severity_color}]",
                issue['component'],
                issue['message']
            )
            
        self.console.print(table)

@click.group()
def cli():
    """Replicated Support Bundle Analyzer"""
    pass

@cli.command()
@click.argument('bundle_path', type=click.Path(exists=True))
def analyze(bundle_path):
    """Analyze a Replicated support bundle"""
    analyzer = SupportBundleAnalyzer(bundle_path)
    analyzer.analyze()

if __name__ == '__main__':
    cli() 