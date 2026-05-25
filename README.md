Cloud-Native SIEM & Threat Detection Lab (Microsoft Sentinel)

## Objective

This hands-on security lab demonstrates the implementation of a cloud-native SIEM (Microsoft Sentinel) ecosystem designed to ingest, parse, 
and analyze real-world endpoint security telemetry. 

The core objective was to establish an enterprise-grade logging pipeline, execute simulated adversarial attacks (RDP Brute Force), and 
engineer threshold-based custom KQL analytic alert rules to detect and alert on unauthorized activity.

## Technologies & Tools Used

  * **SIEM / Cloud Platform:** Microsoft Sentinel & Azure Log Analytics Workspaces
  * **Endpoint Telemetry:** Windows Server 2022 Data Center Compute Node
  * **Ingestion Engine:** Azure Monitor Agent (AMA) & Data Collection Rules (DCR)
  * **Log Enrichment:** Advanced Security Auditing Policies (`auditpol`)
  * **Query Language:** Kusto Query Language (KQL)
  * **Automation:** PowerShell (Adversarial Simulation)

## Architecture & Data Flow Diagram

  [Your Virtual Machine Container]
  │
  ▼ (Advanced Security Auditing Activated)
  [Windows Security Event Log: ID 4625]
  │
  ▼ (Pushed via Azure Monitor Agent)
  [Azure Log Analytics Workspace]
  │
  ▼ (Parsed & Evaluated)
  [Microsoft Sentinel SIEM Workspace] ──> [Custom KQL Analytic Alert Rule Fired]

## Lab Walkthrough & Configuration

  ### Phase 1: Endpoint Hardening & Log Enrichment
  1. Provisioned a Windows Server instance inside Azure to simulate a vulnerable enterprise target endpoint.
  2. Utilized the command line to invoke Windows `auditpol` components, explicitly expanding coverage for the subcategories of
     **"Account Logon"** and **"Logon/Logoff"**. This explicitly forced the operating system to pass full event data payloads to
     the local security ledger.
  
  ### Phase 2: Adversarial Attack Simulation (RDP Brute Force)
  1. Logged into the compute node and initiated an administrative PowerShell terminal.
  2. Executed a customized scripting loop to simulate an online brute-force attempt targeting administrative pathways:
     ```powershell
     1..15 | ForEach-Object { net use \\127.0.0.1\c$ /user:FakeAdmin WrongPassword$_ 2>$null }
  3. This step generated a spike of consecutive Event ID 4625 (An account failed to log on) security events using non-existent
     credentials (FakeAdmin).\
     
  ### Phase 3: Ingestion Configuration & Custom KQL Detection Engineering
  1. Deployed the Windows Security Events via AMA connector package through the Microsoft Content Hub.
  2. Constructed a dedicated Data Collection Rule (DCR) to bind the targeted Windows virtual machine to the Sentinel Log Analytics
     Workspace.
  3. Authored a production-ready, threshold-based KQL tracking query to isolate unauthorized brute-force spikes (5+ authentication
     failures within a 5-minute rolling window):
     
    Code snippet:
    
    SecurityEvent
    | where EventID == 4625
    | summarize FailureCount = count() by TargetUserName, SourceComputerId, bin(TimeGenerated, 5m)
    | where FailureCount >= 5

## Verification & Artifacts

  1. KQL Detection Execution Results
    The screenshot below confirms that the SIEM successfully ingested the endpoint telemetry and that our custom KQL tracking logic
    flawlessly isolated the unauthorized brute force attempts against the FakeAdmin user profile.

  2. Live Sentinel Incident Activation Dashboard
    Once the KQL filter logic was mapped into a Scheduled Analytics Alert Rule, re-triggering the attack script successfully forced
    Microsoft Sentinel to parse the database anomalies, declare an operational incident, and route a ticket to the analyst triage queue.
