import asyncio
import os
import json
import logging
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
from pydantic import AnyUrl, BaseModel
import mcp.server.stdio
import dotenv
import sys
from datetime import datetime, timedelta
from illumio import *
from illumio.util.jsonutils import Reference
from illumio.explorer.trafficanalysis import TrafficQueryFilter
import pandas as pd
from json import JSONEncoder
from pathlib import Path

def setup_logging():
    """Configure logging based on environment"""
    logger = logging.getLogger('illumio_mcp')
    logger.setLevel(logging.DEBUG)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Determine log path based on environment
    if os.environ.get('DOCKER_CONTAINER'):
        log_path = Path('/var/log/illumio-mcp/illumio-mcp.log')
    else:
        # Use home directory for local logging
        log_path = './illumio-mcp.log'
    
    file_handler = logging.FileHandler(str(log_path))
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    
    # Prevent logs from propagating to root logger
    logger.propagate = False
    
    return logger

# Initialize logging
logger = setup_logging()
logger.debug("Loading environment variables")

dotenv.load_dotenv()

PCE_HOST = os.getenv("PCE_HOST")
PCE_PORT = os.getenv("PCE_PORT")
PCE_ORG_ID = os.getenv("PCE_ORG_ID")
API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")

MCP_BUG_MAX_RESULTS = 500

server = Server("illumio-mcp")
logging.debug("Server initialized")

# ---------------------------------------------------------------------------
# Illumio Knowledge Base — MCP Resources
# ---------------------------------------------------------------------------
# These resources provide persistent domain knowledge to the LLM so it
# understands Illumio concepts without relying solely on tool descriptions.

ILLUMIO_RESOURCES = {
    "illumio://concepts/rule-processing": {
        "name": "Illumio Rule Processing Order",
        "description": "How Illumio processes rules — essential for understanding policy behavior",
        "content": """# Illumio Rule Processing Order

Rules in Illumio are processed in strict priority order. Understanding this is CRITICAL for correct policy design.

## Processing Order (highest to lowest priority)

1. **Essential rules** — Built-in rules that cannot be modified. Always processed first.

2. **Override Deny rules** — BLOCK traffic, overriding ALL allow rules below them.
   - Created via the deny_rules API with `"override": true`
   - These deny traffic regardless of any allow rules — "this must not happen under any circumstances"
   - Use cases:
     - Emergency isolation of compromised systems
     - Hard compliance blocks (e.g., PCI zones that must never reach the internet)
     - Blocking an active attack vector
     - Any scenario where no allow rule should ever override the block
   - NEVER use override deny for normal segmentation or ringfencing — use regular deny rules instead
   - Example: "Block ALL traffic to app X immediately" or "PCI zone must never reach external networks"

3. **Allow rules** — Normal rules in rulesets that permit specific traffic.
   - This is where ringfence rules live (both intra-scope and extra-scope)
   - Processed AFTER override deny, so override deny wins if both match

4. **Deny rules** — Block specific traffic (regular deny, NOT override).
   - Created via the deny_rules API with `"override": false`
   - Processed AFTER allow rules, so allow rules take precedence
   - Used in selective enforcement ringfencing to block unknown inbound traffic
   - Known remote apps get allow rules (step 3) which are processed before this deny (step 4)

5. **Default action** — What happens when no rule matches:
   - **Selective enforcement mode**: default = ALLOW ALL (deny rules are actively enforced, everything else passes)
   - **Full enforcement mode**: default = DENY ALL (only explicitly allowed traffic passes)

## Key Implications

- Override Deny > Allow > Deny > Default
- In selective mode, you NEED a deny rule to block anything (default is allow-all)
- In full enforcement, you NEED allow rules to permit anything (default is deny-all)
- Override deny should NEVER be used for routine segmentation — it's for emergencies only
- Ringfencing uses regular deny rules (step 4) + allow rules (step 3), never override deny (step 2)
"""
    },
    "illumio://concepts/enforcement-modes": {
        "name": "Illumio Enforcement Modes",
        "description": "Enforcement modes control how policy rules affect workload traffic",
        "content": """# Illumio Enforcement Modes

Each workload has an enforcement mode that determines how policy affects its traffic.

## Modes (from least to most restrictive)

### Idle
- No policy enforcement at all
- VEN is installed but not actively managing firewall rules
- Used during initial deployment or troubleshooting

### Visibility Only
- VEN reports traffic flows but does NOT enforce any rules
- All traffic is allowed regardless of policy
- Used for traffic discovery and policy modeling before enforcement

### Selective Enforcement
- Default action is **ALLOW ALL**
- Only **deny rules** are actively enforced
- Allow rules exist for documentation/visibility but don't change traffic behavior
- Use case: "I want to block specific things but allow everything else"
- Ringfencing in selective mode requires a deny rule to be effective
- Good stepping stone between visibility and full enforcement

### Full Enforcement
- Default action is **DENY ALL**
- Only traffic explicitly permitted by allow rules can pass
- Most restrictive and most secure mode
- Use case: "Only explicitly allowed traffic should flow"
- Requires comprehensive policy before enabling — missing rules will break connectivity

## Recommended Rollout Order

1. **Visibility Only** — discover traffic patterns, build policy
2. **Selective Enforcement** — enforce deny rules, validate allow rules don't break anything
3. **Full Enforcement** — flip to deny-all default once policy is comprehensive

## Mixed Enforcement Warning
Having workloads in the same app with different enforcement modes is a common issue during rollouts. Use `get-workload-enforcement-status` to detect this.
"""
    },
    "illumio://concepts/segmentation": {
        "name": "Illumio Segmentation & Ringfencing",
        "description": "Core concepts for application segmentation and ringfencing",
        "content": """# Illumio Segmentation Concepts

## Labels
Illumio uses a label system (not traditional network zones) to identify workloads:
- **Role** — what the workload does (web, db, app-server)
- **Application** — which application it belongs to (CRM, Ordering, ELK)
- **Environment** — deployment environment (Production, Staging, Development)
- **Location** — physical or logical location (US-East, Cloud, DC1)

An application is uniquely identified by its **app + env** label combination.

## Rulesets and Scopes
- A **ruleset** contains rules and has one or more **scopes**
- A scope defines which workloads the ruleset applies to (e.g., app=CRM, env=Production)
- Rules within a ruleset are either:
  - **Intra-scope** — traffic between workloads inside the scope (unscoped_consumers=false)
  - **Extra-scope** — traffic from outside the scope into it (unscoped_consumers=true)

## Ringfencing
Ringfencing = coarse-grained app-to-app segmentation on All Services:

### Standard Ringfence
1. Create a ruleset scoped to [app, env]
2. Add an intra-scope allow rule: All Workloads -> All Workloads on All Services
3. For each remote app that needs access, add an extra-scope allow rule

### Selective Ringfence
Same as standard, plus:
4. Add a **deny rule** (regular, NOT override deny) blocking all inbound
5. The deny rule (step 4 in processing) catches unknown traffic
6. Allow rules for known remote apps (step 3 in processing) are processed first, so they pass through

### Override Deny is NOT for Ringfencing
Override deny blocks traffic above ALL allow rules. If you use it for ringfencing, your allow rules for known remote apps won't work because override deny is processed first. Override deny means "this traffic must not happen under any circumstances" — use it for emergency isolation, hard compliance blocks, or active attack response. Never for routine segmentation.

## Deny Consumer Flavors
Controls where the deny rule is enforced (Illumio writes deny rules to the consumer/source side):
- **`any`** — Consumer = IP list "Any (0.0.0.0/0)". Deny only at destination workloads. Safest.
- **`ams`** — Consumer = All Workloads. Deny pushed to every managed source workload. Broader.
- **`ams_and_any`** — Both. Maximum coverage.

## Policy Coverage
Traffic flows have a `policy_decision`:
- **allowed** — covered by active allow rules
- **potentially_blocked** — would be blocked if draft policy were provisioned
- **blocked** — currently blocked by active policy

When creating ringfence rules, remote apps are tagged:
- **already_allowed** — all flows already covered by existing policy (rule created for documentation)
- **newly_allowed** — at least one flow would be blocked without the new rule (filling a gap)

## Infrastructure Services
Infrastructure services (DNS, AD, monitoring) should be policy'd FIRST because many apps depend on them. Use `identify-infrastructure-services` to find them. If you ringfence an app before allowing its infrastructure dependencies, you break it.
"""
    },
    "illumio://concepts/draft-active-policy": {
        "name": "Illumio Draft vs Active Policy",
        "description": "Understanding draft and active policy states and provisioning",
        "content": """# Draft vs Active Policy

Illumio uses a two-stage policy model:

## Draft Policy
- All mutations (create, update, delete) go to `/sec_policy/draft/`
- Draft changes are NOT enforced — they're a staging area
- Multiple changes can be accumulated before provisioning
- Draft policy can be simulated: traffic flows show `potentially_blocked` for flows that WOULD be blocked if the draft were provisioned

## Active Policy
- Currently enforced policy at `/sec_policy/active/`
- Read-only — cannot be modified directly
- Only changes when draft policy is provisioned

## Provisioning
- Moves draft changes to active state
- Use `provision-policy` tool to provision
- Use `compare-draft-active` to preview what would change
- Always review draft changes before provisioning
- Provisioning is atomic — all changes go live at once

## Policy Simulation
The `policy_decision` field on traffic flows is extremely powerful:
- Shows what would happen if current draft policy were active
- `potentially_blocked` = "this traffic would break if you provision"
- Use this to validate policy BEFORE enforcing it
- The `enforcement-readiness` tool uses this to assess readiness
"""
    },
    "illumio://compliance/pci-dss": {
        "name": "PCI-DSS Segmentation & Visibility Requirements",
        "description": "PCI-DSS v4.0 requirements mapped to Illumio segmentation and visibility controls",
        "content": """# PCI-DSS v4.0 — Segmentation & Visibility with Illumio

## Overview
PCI-DSS requires organizations that handle cardholder data to implement strict network segmentation
and access controls. Illumio provides micro-segmentation that directly maps to PCI requirements.

## Key Concept: Cardholder Data Environment (CDE)
The CDE includes all systems that store, process, or transmit cardholder data, plus any systems
directly connected to or supporting those systems. Proper segmentation REDUCES PCI scope by
isolating the CDE from the rest of the network.

## Requirement Mapping

### Requirement 1: Install and Maintain Network Security Controls
- **1.2.1** — Network security controls (NSCs) must restrict traffic between CDE and untrusted networks
  - Illumio: Ringfence CDE apps with `create-ringfence` using `selective=true`
  - Override deny for absolute blocks: CDE must NEVER reach certain external networks
- **1.2.5** — All services, protocols, and ports allowed must be documented and authorized
  - Illumio: `get-traffic-flows-summary` shows all observed services with policy decisions
  - `get-policy-coverage-report` identifies gaps between observed traffic and policy
- **1.3.1** — Inbound traffic to the CDE must be restricted to only necessary traffic
  - Illumio: Extra-scope allow rules in ringfence rulesets explicitly permit inbound sources
  - All other inbound is blocked by deny rule (selective) or default deny (full enforcement)
- **1.3.2** — Outbound traffic from the CDE must be restricted to only necessary traffic
  - Illumio: Create outbound rulesets scoped to CDE apps with explicit allow rules
- **1.4.1** — NSCs between trusted and untrusted networks must be implemented
  - Illumio: Enforcement mode must be `selective` or `full` for CDE workloads
  - `get-workload-enforcement-status` verifies all CDE workloads are enforced

### Requirement 2: Apply Secure Configurations
- **2.2.4** — Only necessary services, protocols, daemons, and functions are enabled
  - Illumio: `find-unmanaged-traffic` detects unauthorized services
  - Traffic flow analysis shows unnecessary port exposure

### Requirement 6: Develop and Maintain Secure Systems
- **6.4.1** — Public-facing web applications must be protected
  - Illumio: Identify internet-facing workloads via traffic flows from unmanaged IPs
  - Ringfence public-facing apps separately from internal CDE systems

### Requirement 7: Restrict Access to System Components
- **7.2.1** — Access control systems must restrict access based on business need
  - Illumio: Label-based policy ensures only authorized apps reach CDE
  - `compliance-check framework=pci-dss` validates rule coverage
- **7.2.5** — All application and system accounts are assigned least privilege
  - Illumio: Granular rules per port/protocol instead of "All Services" for CDE

### Requirement 10: Log and Monitor All Access
- **10.2.1** — Audit logs capture all access to cardholder data
  - Illumio: `get-events` provides PCE audit trail
  - Traffic flows serve as network-level access logs
- **10.4.1** — Audit logs are reviewed to identify anomalies
  - Illumio: `detect-lateral-movement-paths` identifies unexpected connectivity

### Requirement 11: Test Security Systems and Processes
- **11.4.1** — Penetration testing validates segmentation controls
  - Illumio: `enforcement-readiness` assesses policy completeness
  - `compare-draft-active` ensures no policy drift

## PCI-Specific High-Risk Ports
These ports require explicit allow rules and should NEVER be open to/from CDE without justification:
- **3389** (RDP) — Remote Desktop, primary attack vector
- **22** (SSH) — Secure Shell, limit to jump hosts only
- **23** (Telnet) — MUST be blocked, unencrypted protocol
- **445** (SMB) — Windows file sharing, lateral movement vector
- **1433** (MSSQL), **3306** (MySQL), **5432** (PostgreSQL), **1521** (Oracle) — Database ports, CDE core
- **27017** (MongoDB), **6379** (Redis) — NoSQL databases
- **135/139** (NetBIOS/RPC) — Windows infrastructure, restrict within CDE only

## Segmentation Validation Strategy
1. Use `identify-infrastructure-services` to find shared services CDE depends on
2. Ringfence CDE apps with `create-ringfence` (selective mode for gradual rollout)
3. Use `enforcement-readiness` to assess each CDE app before moving to full enforcement
4. Run `compliance-check framework=pci-dss` to validate against requirements
5. Use `get-policy-coverage-report` to prove all CDE traffic is policy-covered
6. Document with `get-traffic-flows-summary` showing only authorized flows remain
"""
    },
    "illumio://compliance/dora": {
        "name": "DORA (Digital Operational Resilience Act) Requirements",
        "description": "EU DORA regulation mapped to Illumio segmentation and operational resilience controls",
        "content": """# DORA — Digital Operational Resilience Act with Illumio

## Overview
DORA (EU Regulation 2022/2554) requires financial entities to ensure digital operational resilience
through ICT risk management, incident reporting, resilience testing, and third-party risk management.
Effective January 17, 2025.

## Who Must Comply
Banks, insurance companies, investment firms, payment institutions, crypto-asset service providers,
and critical ICT third-party service providers operating in the EU.

## Requirement Mapping

### Chapter II: ICT Risk Management Framework (Articles 5-16)

#### Article 6: ICT Risk Management Framework
- **6.8** — Identify, classify, and document all ICT assets and dependencies
  - Illumio: `get-workloads` with label filtering provides complete asset inventory
  - `identify-infrastructure-services` maps critical ICT dependencies
  - Labels (app, env, role, loc) classify assets by function and criticality

#### Article 7: ICT Systems, Protocols, and Tools
- **7.1** — Use resilient, reliable ICT systems with sufficient capacity
  - Illumio: `get-workload-enforcement-status` ensures protection is active
  - Monitor enforcement mode consistency across critical systems

#### Article 8: Identification
- **8.1** — Identify and document all ICT-supported business functions and assets
  - Illumio: Traffic flow analysis reveals actual application dependencies
  - `get-traffic-flows-summary` documents communication patterns
  - `find-unmanaged-traffic` identifies undocumented ICT assets

#### Article 9: Protection and Prevention
- **9.1** — Continuously monitor and control ICT system security
  - Illumio: Micro-segmentation prevents lateral movement between systems
  - `detect-lateral-movement-paths` identifies potential propagation paths
- **9.2** — Implement policies to restrict network access
  - Illumio: `create-ringfence` enforces app-level segmentation
  - Enforcement modes control traffic at the workload level
- **9.3** — Design network connectivity to allow immediate severing/isolation
  - Illumio: Override deny rules can instantly isolate compromised systems
  - `emergency-isolate-application` prompt provides guided isolation workflow
  - Isolation is immediate — no firewall change requests needed

#### Article 10: Detection
- **10.1** — Detect anomalous activities, network performance issues, ICT incidents
  - Illumio: `get-events` monitors PCE events with severity filtering
  - Traffic flow analysis detects unauthorized communication patterns
  - `find-unmanaged-traffic` surfaces unknown connections

#### Article 11: Response and Recovery
- **11.1** — ICT business continuity policy with response and recovery plans
  - Illumio: Segmentation limits blast radius of incidents
  - Override deny enables immediate containment
  - `compare-draft-active` ensures recovery policy is ready to provision
- **11.3** — Activate response plans upon ICT-related incidents
  - Illumio: `emergency-isolate-application` provides one-click isolation
  - `provision-policy` can rapidly deploy pre-staged containment rules

### Chapter III: ICT-Related Incident Management (Articles 17-23)

#### Article 17: ICT-Related Incident Management Process
- **17.1** — Classify and report ICT incidents by impact and severity
  - Illumio: `get-events` with severity filters supports incident classification
  - Traffic flows provide forensic evidence of incident scope

#### Article 18: Classification of ICT-Related Incidents
- Map incident severity to segmentation response:
  - **Critical**: Override deny — immediate isolation
  - **Major**: Selective enforcement — restrict to known-good traffic
  - **Minor**: Monitor via visibility mode, draft new rules as needed

### Chapter IV: Digital Operational Resilience Testing (Articles 24-27)

#### Article 25: Testing ICT Tools and Systems
- **25.1** — Perform vulnerability assessments, network security assessments
  - Illumio: `compliance-check` validates segmentation policy
  - `enforcement-readiness` assesses enforcement completeness
  - `get-policy-coverage-report` measures policy coverage

#### Article 26: Advanced Testing (TLPT)
- **26.1** — Threat-led penetration testing for significant financial entities
  - Illumio: `detect-lateral-movement-paths` maps potential attack paths
  - Segmentation effectiveness can be validated without disruption using visibility mode

### Chapter V: Third-Party Risk Management (Articles 28-44)

#### Article 28: ICT Third-Party Risk
- **28.1** — Manage risks from ICT third-party service providers
  - Illumio: `find-unmanaged-traffic` reveals third-party connections
  - Ringfence third-party integration points
  - Monitor third-party traffic patterns for anomalies

## DORA-Specific Segmentation Strategy
1. **Identify**: Use `identify-infrastructure-services` + `get-workloads` to map all ICT assets
2. **Classify**: Label workloads by criticality and business function
3. **Protect**: Ringfence critical financial services, enforce segmentation
4. **Detect**: Monitor traffic flows for anomalous patterns
5. **Respond**: Pre-stage override deny rules for critical systems, test isolation procedures
6. **Recover**: Use `compare-draft-active` to manage recovery policy, provision when ready

## Key DORA Principle: Immediate Isolation Capability
DORA Article 9.3 specifically requires the ability to immediately sever/isolate affected systems.
Illumio's override deny rules provide this — they block traffic instantly, overriding any allow rules.
This maps directly to DORA's requirement for rapid containment during ICT incidents.
"""
    },
    "illumio://compliance/nist-800-53": {
        "name": "NIST 800-53 Security Controls",
        "description": "NIST 800-53 Rev 5 controls mapped to Illumio segmentation capabilities",
        "content": """# NIST 800-53 Rev 5 — Security Controls with Illumio

## Overview
NIST 800-53 provides a catalog of security and privacy controls for federal information systems.
Many private sector organizations adopt it as a comprehensive security framework.

## Control Family Mapping

### AC — Access Control

#### AC-3: Access Enforcement
- Enforce approved authorizations for logical access to information and system resources
- Illumio: Label-based policy enforces access at the workload level
- Rulesets define exactly which apps can communicate with which
- `get-policy-coverage-report` validates enforcement completeness

#### AC-4: Information Flow Enforcement
- Enforce approved authorizations for controlling the flow of information within the system
  and between connected systems
- Illumio: Micro-segmentation controls east-west traffic flows
- Ringfencing enforces app-to-app communication policies
- Policy decisions (allowed/blocked/potentially_blocked) show flow enforcement status
- **AC-4(21)** Physical/logical separation of information flows
  - Illumio: Labels create logical separation without physical network changes

#### AC-17: Remote Access
- Establish usage restrictions and implementation guidance for remote access
- Illumio: Control which systems remote access (RDP 3389, SSH 22, VNC 5900) can reach
- High-risk ports must have explicit allow rules only to authorized destinations

### AU — Audit and Accountability

#### AU-2: Event Logging
- Identify events that the system must log
- Illumio: `get-events` provides comprehensive PCE event logging
- Traffic flows serve as network-level audit trail

#### AU-6: Audit Record Review, Analysis, and Reporting
- Review and analyze audit records for indications of inappropriate or unusual activity
- Illumio: `detect-lateral-movement-paths` analyzes traffic for unusual patterns
- `find-unmanaged-traffic` identifies unauthorized connections

### CA — Assessment, Authorization, and Monitoring

#### CA-7: Continuous Monitoring
- Develop a continuous monitoring strategy and implement a program
- Illumio: Continuous traffic flow visibility across all workloads
- `enforcement-readiness` provides ongoing readiness assessment
- `compliance-check` can be run periodically for compliance validation

### CM — Configuration Management

#### CM-7: Least Functionality
- Configure the system to provide only essential capabilities
- Restrict the use of unnecessary ports, protocols, functions, and services
- Illumio: Traffic analysis reveals unnecessary services
- `find-unmanaged-traffic` identifies services outside policy
- Ringfencing limits each app to only its required connectivity

### IA — Identification and Authentication

#### IA-3: Device Identification and Authentication
- Uniquely identify and authenticate devices before establishing connections
- Illumio: VEN agents on workloads provide device-level identification
- Labels provide logical identity for policy decisions

### IR — Incident Response

#### IR-4: Incident Handling
- Implement an incident handling capability including preparation, detection, containment
- Illumio: Override deny rules provide immediate containment
- `emergency-isolate-application` enables rapid incident response
- Segmentation limits blast radius during incidents

#### IR-6: Incident Reporting
- Report incidents to appropriate authorities and organizational entities
- Illumio: `get-events` provides incident evidence and audit trail
- Traffic flow data supports forensic analysis

### SC — System and Communications Protection

#### SC-7: Boundary Protection
- Monitor and control communications at external managed interfaces and key internal boundaries
- Illumio: Micro-segmentation creates boundaries at every workload
- `create-ringfence` establishes application-level boundaries
- `get-workload-enforcement-status` verifies boundary enforcement
- **SC-7(5)** Deny by default / allow by exception
  - Illumio: Full enforcement mode = deny-all default, only explicitly allowed traffic passes
  - Selective enforcement = allow-all default with explicit deny rules

#### SC-28: Protection of Information at Rest
- Protect the confidentiality and integrity of information at rest
- Illumio: Segment database systems containing sensitive data
- Override deny blocks ensure critical data stores are never exposed

### SI — System and Information Integrity

#### SI-4: System Monitoring
- Monitor the system to detect attacks, unauthorized connections, and anomalies
- Illumio: Traffic flow analysis detects unauthorized network activity
- `detect-lateral-movement-paths` identifies potential attack paths
- `find-unmanaged-traffic` surfaces unknown connections

## NIST High-Risk Ports
Ports requiring explicit authorization under NIST controls:
- **22** (SSH), **23** (Telnet), **3389** (RDP) — Remote access
- **135/139** (NetBIOS/RPC), **445** (SMB) — Windows services
- **1433** (MSSQL), **3306** (MySQL), **5432** (PostgreSQL) — Databases
- **80/443** (HTTP/HTTPS) — Web services (restrict from internal systems to CDE)
"""
    },
    "illumio://compliance/iso-27001": {
        "name": "ISO 27001:2022 Controls",
        "description": "ISO 27001:2022 Annex A controls mapped to Illumio segmentation capabilities",
        "content": """# ISO 27001:2022 — Information Security Controls with Illumio

## Overview
ISO 27001:2022 is the international standard for information security management systems (ISMS).
Annex A contains 93 controls organized into 4 themes. Network segmentation maps to multiple controls.

## Annex A Control Mapping

### A.5 — Organizational Controls

#### A.5.9: Inventory of Information and Other Associated Assets
- Maintain an inventory of information and associated assets
- Illumio: `get-workloads` provides workload inventory with labels
- Labels classify assets by app, env, role, and location
- `identify-infrastructure-services` maps critical dependencies

#### A.5.23: Information Security for Use of Cloud Services
- Establish processes for acquisition, use, management, and exit of cloud services
- Illumio: Segment cloud workloads with same label-based policy as on-premises
- `find-unmanaged-traffic` identifies cloud service dependencies

#### A.5.25: Assessment and Decision on Information Security Events
- Assess information security events and decide if they are incidents
- Illumio: `get-events` provides security event visibility
- Traffic flows provide evidence for event assessment

### A.8 — Technological Controls

#### A.8.20: Networks Security
- Secure networks and network services, including mechanisms for filtering traffic
- Illumio: Micro-segmentation provides workload-level traffic filtering
- `create-ringfence` establishes network security boundaries
- `get-workload-enforcement-status` validates security is active

#### A.8.21: Security of Network Services
- Identify and implement security mechanisms, service levels, and requirements
- Illumio: Policy-driven segmentation ensures consistent network security
- `compliance-check` validates control effectiveness

#### A.8.22: Segregation of Networks
- Groups of information services, users, and information systems shall be segregated
- Illumio: Label-based segmentation segregates by application, environment, and role
- Ringfencing provides coarse-grained segregation
- Fine-grained rules provide per-port/protocol controls within segments
- `detect-lateral-movement-paths` validates segregation effectiveness

#### A.8.23: Web Filtering
- Access to external websites shall be managed to reduce exposure to malicious content
- Illumio: Outbound traffic rules control which systems can reach external services
- `find-unmanaged-traffic` direction=outbound identifies uncontrolled outbound connections

#### A.8.26: Application Security Requirements
- Information security requirements shall be identified and specified when developing/acquiring applications
- Illumio: `enforcement-readiness` validates security completeness per application
- `get-policy-coverage-report` measures policy coverage

## ISO 27001 Segmentation Best Practices
1. **Classify** assets using Illumio labels (app, env, role, loc)
2. **Segregate** using ringfencing between applications and environments
3. **Enforce** with progressive enforcement (visibility → selective → full)
4. **Monitor** with continuous traffic flow analysis
5. **Audit** with compliance checks and event monitoring
6. **Improve** using enforcement readiness scores to track progress
"""
    },
    "illumio://compliance/swift-csp": {
        "name": "SWIFT Customer Security Programme (CSP)",
        "description": "SWIFT CSP controls mapped to Illumio segmentation for financial messaging security",
        "content": """# SWIFT CSP — Customer Security Programme with Illumio

## Overview
SWIFT's Customer Security Programme (CSP) establishes mandatory security controls for all
organizations connected to the SWIFT network. The secure zone containing SWIFT infrastructure
must be strictly segmented from the rest of the enterprise network.

## Key Concept: SWIFT Secure Zone
The SWIFT secure zone contains all SWIFT-related components:
- SWIFT messaging interfaces (Alliance Lite2, Alliance Access, Alliance Gateway)
- SWIFT communication interfaces
- Operator PCs used to access SWIFT
- Any system that directly connects to SWIFT infrastructure

This zone MUST be isolated from the general enterprise network.

## Mandatory Control Mapping

### 1. Restrict Internet Access & Protect Critical Systems

#### 1.1: SWIFT Environment Protection
- Ensure the protection of the SWIFT infrastructure from the general IT environment
- Illumio: Ringfence SWIFT zone apps with `create-ringfence selective=true`
- Override deny to block SWIFT zone from internet access entirely
- Only explicitly authorized systems can reach SWIFT components

#### 1.2: Operating System Privileged Account Control
- Restrict and control privileged OS account usage within the SWIFT secure zone
- Illumio: Limit SSH (22) and RDP (3389) access to SWIFT systems to jump hosts only
- Explicit allow rules only for authorized admin connections

#### 1.4: Restriction of Internet Access
- SWIFT-connected systems must not have direct internet access
- Illumio: **Override deny rule** blocking all traffic from SWIFT zone to internet IPs
- This is a "must not happen under any circumstances" scenario — override deny is correct here
- `find-unmanaged-traffic` validates no unauthorized internet connections exist

### 2. Reduce Attack Surface and Vulnerabilities

#### 2.1: Internal Data Flow Security
- Ensure confidentiality, integrity, and authentication of data flows between SWIFT components
- Illumio: Intra-scope rules control traffic within SWIFT zone
- Enforce specific port/protocol rules (not All Services) between SWIFT components

#### 2.6: Operator Session Confidentiality and Integrity
- Protect operator sessions to SWIFT-related applications
- Illumio: Allow only encrypted protocols (SSH, HTTPS) from operator PCs to SWIFT systems
- Block unencrypted protocols (Telnet 23, HTTP 80, FTP 21)

### 3. Physically Secure the Environment
(Physical controls — Illumio supports with logical segmentation of location-labeled workloads)

### 4. Prevent Compromise of Credentials

#### 4.1: Password Policy
- Enforce strong password policies for SWIFT system accounts
- Illumio: Complements by ensuring only authorized systems can attempt authentication

### 5. Manage Identities and Segregate Privileges

#### 5.1: Logical Access Control
- Enforce least-privilege access to SWIFT systems
- Illumio: Fine-grained rules restrict SWIFT zone access to specific source apps/roles
- `get-policy-coverage-report` validates all SWIFT traffic is explicitly authorized

### 6. Detect Anomalous Activity

#### 6.1: Malware Protection
- Detect and prevent malware in the SWIFT secure zone
- Illumio: Segmentation prevents malware lateral movement into/within SWIFT zone
- `detect-lateral-movement-paths` identifies potential propagation vectors

#### 6.4: Logging and Monitoring
- Record and monitor security events in the SWIFT secure zone
- Illumio: `get-events` monitors SWIFT-related policy events
- Traffic flows provide network-level audit trail for SWIFT zone

## SWIFT-Specific High-Risk Ports
Ports requiring strict control in the SWIFT secure zone:
- **3389** (RDP), **22** (SSH) — Admin access, restrict to jump hosts
- **23** (Telnet), **21** (FTP) — MUST be blocked (unencrypted)
- **80** (HTTP) — Block in favor of HTTPS only
- **1433/3306/5432** — Database access, restrict to SWIFT application servers
- **445** (SMB), **135/139** (NetBIOS) — Block within SWIFT zone

## SWIFT Segmentation Strategy
1. Label all SWIFT components with dedicated app label (e.g., app=SWIFT)
2. Create SWIFT secure zone ringfence with `create-ringfence selective=true`
3. Add **override deny** blocking SWIFT zone → internet (must never happen)
4. Add explicit allow rules for authorized connections only
5. Validate with `compliance-check` and `get-policy-coverage-report`
6. Move to full enforcement after validation
"""
    },
    "illumio://compliance/cis-controls": {
        "name": "CIS Controls v8",
        "description": "CIS Critical Security Controls v8 mapped to Illumio segmentation capabilities",
        "content": """# CIS Controls v8 — Critical Security Controls with Illumio

## Overview
The CIS Critical Security Controls (formerly SANS Top 20) are a prioritized set of actions
to protect organizations from known cyber-attack vectors. Illumio maps to several controls
in the network and data protection domains.

## Control Mapping

### CIS Control 1: Inventory and Control of Enterprise Assets
- Actively manage all enterprise assets connected to the network
- Illumio: `get-workloads` provides managed asset inventory
- `find-unmanaged-traffic` reveals assets not yet under management
- Labels provide classification (app, env, role, location)

### CIS Control 2: Inventory and Control of Software Assets
- Actively manage all software on the network
- Illumio: Traffic flow analysis reveals which services/ports are in use
- Unexpected services indicate unauthorized software

### CIS Control 3: Data Protection
- Develop processes and controls to identify, classify, securely handle data
- Illumio: Segment systems handling sensitive data with ringfencing
- Override deny for systems that must never expose data externally

### CIS Control 4: Secure Configuration of Enterprise Assets and Software
- Establish and maintain secure configurations
- Illumio: `compliance-check` validates segmentation configuration
- `get-workload-enforcement-status` verifies enforcement is properly configured

### CIS Control 6: Access Control Management
- Use processes and tools to create, assign, manage, and revoke access credentials
- Illumio: Label-based policy controls network-level access
- Rules define exactly which applications can communicate

### CIS Control 7: Continuous Vulnerability Management
- Develop a plan to continuously assess and remediate vulnerabilities
- Illumio: `enforcement-readiness` provides ongoing security posture assessment
- `detect-lateral-movement-paths` identifies vulnerability propagation paths

### CIS Control 8: Audit Log Management
- Collect, alert, review, and retain audit logs of events
- Illumio: `get-events` provides audit log access
- Traffic flows provide network-level audit data

### CIS Control 9: Email and Web Browser Protections
- Improve protections and detections of threats from email and web vectors
- Illumio: Control which systems can reach web/email ports (80, 443, 25, 587)

### CIS Control 12: Network Infrastructure Management
- **12.2** — Establish and maintain a secure network architecture
  - Illumio: Micro-segmentation creates a secure architecture without network redesign
  - `create-ringfence` establishes app-level security boundaries
- **12.3** — Securely manage network infrastructure
  - Illumio: `get-workload-enforcement-status` monitors enforcement health
- **12.8** — Establish and maintain dedicated computing resources for admin work
  - Illumio: Segment admin jump hosts, restrict RDP/SSH to these only

### CIS Control 13: Network Monitoring and Defense
- **13.1** — Centralize security event alerting
  - Illumio: `get-events` provides centralized security events
- **13.3** — Deploy a network intrusion detection solution
  - Illumio: Traffic flow visibility serves as behavior-based detection
  - `detect-lateral-movement-paths` identifies suspicious connectivity
- **13.4** — Perform traffic filtering between network segments
  - Illumio: Core capability — micro-segmentation is traffic filtering
  - `get-policy-coverage-report` validates filtering completeness
- **13.5** — Manage access control for remote assets
  - Illumio: VPN/remote access segmentation via label-based policy

### CIS Control 17: Incident Response Management
- **17.1** — Designate personnel to manage incident handling
- **17.3** — Establish and maintain an incident response plan
  - Illumio: Override deny rules enable immediate containment
  - `emergency-isolate-application` provides guided incident response
  - Pre-stage containment rules in draft policy for rapid deployment

## CIS High-Risk Ports
- **3389** (RDP), **22** (SSH), **23** (Telnet) — Remote access
- **445** (SMB), **135/139** (NetBIOS/RPC) — File sharing / Windows
- **21** (FTP), **69** (TFTP) — File transfer (unencrypted)
- **25/587** (SMTP) — Email servers
"""
    },
    "illumio://compliance/hipaa": {
        "name": "HIPAA Security Rule",
        "description": "HIPAA Security Rule requirements mapped to Illumio segmentation for healthcare data protection",
        "content": """# HIPAA Security Rule — Healthcare Segmentation with Illumio

## Overview
The HIPAA Security Rule requires covered entities and business associates to implement
safeguards to protect electronic Protected Health Information (ePHI). Network segmentation
is a key technical safeguard.

## Key Concept: ePHI Environment
Systems that create, receive, maintain, or transmit ePHI must be identified and protected.
Segmenting ePHI systems reduces the scope of HIPAA compliance requirements.

## Safeguard Mapping

### Administrative Safeguards (§164.308)

#### §164.308(a)(1) — Security Management Process
- Implement policies and procedures to prevent, detect, contain, and correct security violations
- Illumio: Micro-segmentation prevents lateral movement to ePHI systems
- `detect-lateral-movement-paths` identifies potential violation paths
- Override deny enables immediate containment of active violations

#### §164.308(a)(7) — Contingency Plan
- Establish policies for responding to emergencies that damage ePHI systems
- Illumio: `emergency-isolate-application` provides rapid containment
- Pre-staged draft policies enable quick recovery

### Physical Safeguards (§164.310)

#### §164.310(b) — Workstation Use
- Implement policies specifying proper functions and manner of use for workstations
- Illumio: Segment workstations by role, restrict ePHI access to authorized roles

### Technical Safeguards (§164.312)

#### §164.312(a)(1) — Access Control
- Implement technical policies to allow access only to authorized persons/software
- Illumio: Label-based policy restricts ePHI system access to authorized applications
- `create-ringfence` isolates ePHI systems from general network
- `get-policy-coverage-report` validates access control completeness

#### §164.312(b) — Audit Controls
- Implement mechanisms to record and examine activity in systems containing ePHI
- Illumio: Traffic flows provide network-level audit trail
- `get-events` provides system-level audit records

#### §164.312(c)(1) — Integrity
- Protect ePHI from improper alteration or destruction
- Illumio: Segment database systems containing ePHI
- Restrict database port access to authorized application servers only

#### §164.312(d) — Person or Entity Authentication
- Verify identity of persons/entities seeking access to ePHI
- Illumio: Network-level authentication via workload identity (VEN + labels)
- Only authenticated, labeled workloads can reach ePHI systems

#### §164.312(e)(1) — Transmission Security
- Implement technical measures to guard against unauthorized access to ePHI during transmission
- Illumio: Block unencrypted protocols (Telnet, FTP, HTTP) to/from ePHI systems
- Allow only encrypted protocols (SSH, HTTPS, TLS-wrapped database connections)

## HIPAA Segmentation Strategy
1. Label all ePHI systems (app=EMR, app=PACS, app=PatientDB, etc.)
2. Identify ePHI dependencies with `identify-infrastructure-services`
3. Ringfence each ePHI application with strict inbound/outbound controls
4. Block unencrypted protocols to ePHI zone via deny rules
5. Validate with `compliance-check` and `enforcement-readiness`
6. Monitor with continuous traffic flow analysis
"""
    },
    "illumio://compliance/segmentation-methodology": {
        "name": "Segmentation Methodology & Best Practices",
        "description": "General methodology for implementing micro-segmentation with Illumio across any compliance framework",
        "content": """# Segmentation Methodology — Framework-Agnostic Best Practices

## The Segmentation Journey

### Phase 1: Discovery & Visibility
**Goal**: Understand what you have and how it communicates.

1. **Asset Discovery**
   - Deploy VEN agents on all workloads
   - `get-workloads` to inventory managed systems
   - Assign labels: app, env, role, location

2. **Traffic Discovery**
   - Set enforcement mode to `visibility_only`
   - Collect traffic flows for 30-90 days
   - `get-traffic-flows-summary` to understand communication patterns
   - `find-unmanaged-traffic` to identify blind spots

3. **Dependency Mapping**
   - `identify-infrastructure-services` to find critical shared services
   - Map app-to-app dependencies from traffic flows
   - Identify internet-facing vs internal-only applications
   - `detect-lateral-movement-paths` to understand risk exposure

### Phase 2: Policy Design
**Goal**: Design segmentation policy before enforcing it.

1. **Infrastructure First**
   - Policy infrastructure services first (DNS, AD, monitoring, backup)
   - These are consumed by many apps — if you ringfence apps without allowing infra, you break things
   - Use `identify-infrastructure-services` to prioritize

2. **Application Ringfencing**
   - `create-ringfence` for each application (dry_run=true first)
   - Review discovered remote apps and validate they should have access
   - Use `skip_allowed=true` for minimal rulesets or `false` for self-documenting ones

3. **Compliance Zone Isolation**
   - CDE (PCI), SWIFT zone, ePHI systems get additional restrictions
   - Override deny for hard blocks (e.g., "CDE must never reach internet")
   - Fine-grained rules within compliance zones (not just All Services)

4. **Policy Validation**
   - `enforcement-readiness` to assess each app
   - `get-policy-coverage-report` to measure coverage
   - `compare-draft-active` to review pending changes
   - `compliance-check` against relevant framework

### Phase 3: Enforcement Rollout
**Goal**: Progressively enforce policy with minimal disruption.

1. **Selective Enforcement First**
   - Move workloads from `visibility_only` to `selective`
   - Selective mode: default=allow, deny rules are actively enforced
   - This catches gross violations without breaking everything
   - `get-workload-enforcement-status` to track rollout progress

2. **Monitor and Adjust**
   - Watch for `blocked` traffic in flows — is it intentional or a missing rule?
   - `get-policy-coverage-report` shows gaps
   - Add rules for legitimate traffic before moving to full enforcement

3. **Full Enforcement**
   - Move workloads to `full` enforcement
   - Default=deny: only explicitly allowed traffic flows
   - Start with less critical apps, build confidence
   - Critical systems last (after thorough validation)

### Phase 4: Continuous Operations
**Goal**: Maintain and improve segmentation over time.

1. **Ongoing Monitoring**
   - Regular `compliance-check` runs
   - `find-unmanaged-traffic` to catch new unauthorized connections
   - `get-events` for security event monitoring

2. **Policy Drift Detection**
   - `compare-draft-active` to detect uncommitted changes
   - `enforcement-readiness` scores should trend upward

3. **Incident Response**
   - Override deny for emergency isolation
   - `emergency-isolate-application` for guided incident response
   - Pre-stage containment rules in draft policy

## Common Pitfalls
- **Ringfencing without allowing infrastructure** — breaks DNS, AD, monitoring. Always identify infra first.
- **Using override deny for ringfencing** — override deny blocks above allow rules. Your app-level allow rules won't work. Use regular deny.
- **All Services rules everywhere** — coarse for ringfencing, but compliance zones need per-port/protocol rules.
- **Skipping selective enforcement** — going straight to full enforcement breaks things. Use selective as a stepping stone.
- **Not validating with traffic flows** — policy looks good on paper but real traffic patterns may differ. Always verify with actual flow data.
- **Mixed enforcement modes** — inconsistent enforcement within an app creates security gaps. Use `get-workload-enforcement-status` to detect.

## Compliance Framework Quick Reference

| Framework | Focus Area | Key Illumio Tools |
|-----------|-----------|-------------------|
| PCI-DSS | CDE isolation | ringfence, override deny, compliance-check pci-dss |
| DORA | Operational resilience, incident response | ringfence, emergency isolation, enforcement-readiness |
| NIST 800-53 | Comprehensive security controls | all tools |
| ISO 27001 | ISMS, network segregation | ringfence, compliance-check, enforcement-readiness |
| SWIFT CSP | SWIFT secure zone | ringfence, override deny, find-unmanaged-traffic |
| HIPAA | ePHI protection | ringfence, policy-coverage-report, compliance-check |
| CIS Controls | Prioritized cyber defense | identify-infra, ringfence, detect-lateral-movement |
"""
    },
    "illumio://architecture/pce-ven": {
        "name": "PCE & VEN Architecture",
        "description": "Illumio platform architecture — PCE (Policy Compute Engine) and VEN (Virtual Enforcement Node) components, deployment models, and scaling",
        "content": """# Illumio Architecture — PCE & VEN

## Two Core Components

### Policy Compute Engine (PCE)
The PCE is the central brain of Illumio. It:
- Stores all data (workloads, labels, rules, traffic flows)
- Calculates security policy and distributes it to VENs
- Provides the management UI and API
- Can scale to support hundreds of thousands of workloads

### Virtual Enforcement Node (VEN)
The VEN runs on each managed workload. It:
- Reports traffic flows and workload state back to the PCE
- Implements security policy by managing the local host firewall (iptables/Windows Firewall)
- Available for Linux, Windows, Solaris, and AIX
- Lightweight — minimal CPU, RAM, and disk usage
- Upgrades can be pushed centrally from the PCE

## PCE Deployment Options

### Cloud Service (SaaS)
- Managed by Illumio's operations team
- Quick start, no hardware required
- SOC 2-compliant, highly resilient
- Recommended for 0–10,000 workloads or organizations without deep Linux expertise

### On-Premises
- Full control over all PCE operations
- Recommended for 0–250,000 workloads
- Required for strict data residency or custodianship requirements
- Needs Linux servers with specific OS and storage requirements
- Minimum 4 servers per cluster (supports up to 10,000 workloads)
- Larger footprints support up to 25,000 workloads per cluster

### Supercluster (Large Scale)
- Federated set of clusters with near-real-time replication
- For organizations with 25,000+ managed workloads
- Single-pane-of-glass visibility across all clusters
- Each cluster can operate independently during outages
- Common pattern: regional PCE clusters (e.g., Americas, EMEA, APAC)

## Redundancy & High Availability

### Split-Cluster (Metro-Area HA)
- PCE nodes split between two data centers
- Hot-hot deployment — survives total failure of one data center
- Specific latency requirements between the two sites

### Cold-Standby (DR)
- No specific latency requirements
- Can be combined with split-cluster for full DR capability

### VEN Connectivity
- No specific latency requirement between PCE and VEN
- Global deployments work fine (e.g., PCE in North America, VENs in Asia)
- VENs continue enforcing last-known policy if PCE connectivity is lost

## PCE Hardening
- On-premises PCEs need hardening per Illumio's published hardening guide
- Protect against malicious connections and data integrity threats
- Illumio provides tools to implement recommended controls
"""
    },
    "illumio://concepts/workloads": {
        "name": "Workload Types & VEN Deployment",
        "description": "Managed vs unmanaged workloads, VEN deployment strategies, and workload lifecycle",
        "content": """# Illumio Workloads

## What Is a Workload?
A workload is any endpoint on your network:
- Physical or virtual server
- Public cloud instance (AWS EC2, Azure VM, GCP)
- Container
- Storage appliance
- VIP on a load balancer or proxy device
- Any device with an IP address

## Two Types of Workloads

### Managed Workloads
- Have the VEN software installed and activated
- Under full management by Illumio
- VEN provides traffic visibility AND policy enforcement
- VEN reports workload state, open ports, running processes
- Can be in any enforcement mode: idle, visibility_only, selective, full

### Unmanaged Workloads
- Represented in the PCE but do NOT have VEN installed
- Important for modeling — they appear in dependency maps
- Typical for network appliances, legacy systems, or devices that can't run VEN
- Can have labels assigned for policy purposes
- Traffic TO them from managed workloads is visible
- Traffic FROM them is NOT visible (no VEN to report it)
- Use `find-unmanaged-traffic` to identify traffic involving unmanaged workloads

## VEN Deployment Strategy

### Distribution Methods
- **Automation tools**: Chef, Puppet, Ansible for Linux/Windows
- **SCCM**: Push to Windows workloads via Microsoft SCCM
- **Golden image**: Pre-install VEN in your base image, activates on deployment
- **Custom scripting**: SSH to each workload and pull the VEN package

### Deployment Order (recommended)
1. Start small — pilot with a limited set of workloads
2. Deploy to infrastructure/core services first (DNS, AD, backup)
3. Expand to business applications by criticality
4. Create unmanaged workloads for devices that can't run VEN
5. Full coverage is the goal — gaps in VEN deployment = gaps in visibility

### VEN Behavior on Activation
- Immediately establishes communication with the PCE
- Reports local network state (interfaces, open ports, processes)
- Begins providing traffic visibility
- Starts enforcing policy based on its configured enforcement mode

## Enforcement Modes per Workload
Each workload has its own enforcement mode:
- **Idle**: VEN installed but not active
- **Visibility Only**: Reports traffic, no enforcement
- **Selective**: Enforces deny rules only, default=allow
- **Full**: Enforces all rules, default=deny

**Important**: Enforcement mode is set per-workload, not globally. You can have different
modes within the same application during rollout. Use `get-workload-enforcement-status`
to detect mixed enforcement within an app (a common issue during rollouts).

## Workloads and Deny Rules
The design guide predates deny rule features. Key additions:
- **Deny rules** (regular): Written to the consumer (source) workload's firewall
- **Override deny rules**: Block traffic above all allow rules — for emergencies only
- Deny rules only apply to **managed workloads** (unmanaged workloads have no VEN to enforce them)
- The `deny_consumer` parameter controls which workloads receive the deny rule:
  - `any`: Only destination workloads get the deny rule (safest)
  - `ams`: All managed workloads get the deny rule (broader enforcement)
  - `ams_and_any`: Both (maximum coverage)
"""
    },
    "illumio://architecture/labels": {
        "name": "Label Design (R+A+E+L)",
        "description": "Illumio's four-dimensional label model — Role, Application, Environment, Location — design principles, data quality, and governance",
        "content": """# Illumio Label Design — R+A+E+L

## The Four Dimensions

Each workload is identified by up to four labels:

| Dimension | Purpose | Examples |
|-----------|---------|----------|
| **R**ole | Function the workload performs | Web Server, Database, App Server, Load Balancer |
| **A**pplication | Application the workload belongs to | Payroll, CRM, ELK, SAP, Oracle EBS |
| **E**nvironment | Deployment stage | Production, Staging, QA, Development, DR |
| **L**ocation | Physical or logical location | US-East, Cloud-AWS, DC1, London, EMEA |

## Key Design Principles

### Labels Are NOT Groups
Each label dimension is **independent**. Labels combine to form a unique set of security
properties for each workload. A production HR webserver in London inherits policies from:
- All London servers
- All HR servers
- All production webservers
This intersection-based model is what makes Illumio's policy scalable.

### Consistency Within Dimensions
Each dimension should ALWAYS refer to the same logical concept:
- If Role holds application tiers (web, app, db), always use it for tiers
- Don't mix concepts (e.g., don't put sensitivity classifications in the Role dimension)
- Consistent usage enables predictable policy behavior

### Security Policies Use Labels, Not IPs
Policies are written as label-to-label rules:
- "Web servers in Production can connect to Database servers in Production on port 3306"
- NOT "10.0.1.5 can connect to 10.0.2.10 on port 3306"
- When workloads change (scale up/down, IP changes), policy automatically adapts

### Unique Application Identity
An application is identified by **App + Env** label combination:
- App=CRM, Env=Production → one application instance
- App=CRM, Env=Staging → different application instance
- Ringfencing scopes to this combination

## Data Sources for Labels

### Where to Get Label Data
- **CMDB** (ServiceNow, BMC, etc.) — most comprehensive source
- **Cloud metadata** — AWS tags, Azure tags, GCP labels
- **Hostname conventions** — parse app/env/role from naming patterns
- **API integration** — sync labels automatically from external sources
- **Manual entry** — smallest deployments or one-off systems

### Label Data Quality
- Most organizations start with 50-80% accuracy for environment labels
- Other dimensions (app, role) are often lower
- **This is OK** — Illumio is designed to work with incomplete data
- Traffic flow visibility helps you discover and correct labels
- The process of adopting Illumio improves your metadata quality

### Data Governance
- Consider appointing a **data guardian** for label quality
- Automate label sync from authoritative sources via API
- Refresh labels regularly (daily or real-time as changes occur)
- Updates to labels automatically trigger policy recalculation

## Label Design Anti-Patterns
- **Too few labels**: Everything labeled as "App=Server" — no meaningful segmentation
- **Too many roles**: Hundreds of unique roles — policy becomes unmanageable
- **Inconsistent dimensions**: Location sometimes means physical DC, sometimes means region
- **Missing labels**: Workloads without labels can't be targeted by policy
- **Stale labels**: Workload moved to production but still labeled Development

## Labels and Policy Rules
When writing rules, labels define the scope:
- **Ruleset scope**: App=CRM, Env=Production applies rules to all CRM Production workloads
- **Intra-scope rules**: Traffic between workloads in the same scope
- **Extra-scope rules**: Traffic from outside the scope into it
- **Deny rules**: Can target any label combination (but deny rules are NOT in the design guide — they were added later)
"""
    },
    "illumio://methodology/first-principles": {
        "name": "FIRST Principles of Security Segmentation",
        "description": "Illumio's FIRST methodology — Find, Identify, Reach out, Start, Target — the recommended approach to deploying segmentation",
        "content": """# Illumio's FIRST Principles of Security Segmentation

The FIRST Principles provide a structured methodology for deploying micro-segmentation.
Follow these in order for the highest chance of success.

## F — Find Metadata Sources

**Goal**: Know where your workload data lives before you start.

- Identify your CMDB, cloud metadata, hostname conventions, spreadsheets
- Determine which sources can provide which label dimensions (R, A, E, L)
- Assess data quality — 50-80% accuracy for environment labels is typical to start
- Plan how to sync this data to the PCE (API, manual, or hybrid)

**Illumio Tools**: `get-workloads` to see current inventory, labels reveal data gaps

## I — Identify a Label Design

**Goal**: Design your R+A+E+L label model before applying it.

- Role: what does the workload do? (web, db, app-server)
- Application: which application? (CRM, Payroll, SAP)
- Environment: what stage? (Production, Staging, Dev)
- Location: where is it? (physical DC, cloud region, regulatory jurisdiction)
- Keep each dimension consistent — same concept always
- Labels are NOT groups — they combine for unique identity

**Illumio Tools**: `get-label-dimensions` to see current label schema

## R — Reach Out to Service Owners Early

**Goal**: Engage stakeholders before enforcement begins.

- Service owners know their applications' expected traffic patterns
- They can validate dependency maps against expected behavior
- Early engagement prevents surprises when enforcement starts
- Common stakeholders:
  - Application owners (validate app-to-app communication)
  - Network team (understand existing firewall rules)
  - Security team (define compliance requirements)
  - Operations team (identify maintenance and backup traffic)

**Illumio Tools**: `get-traffic-flows-summary` produces dependency reports service owners can review

## S — Start with Core Services

**Goal**: Policy infrastructure services first — they affect everything else.

Core services are consumed by most/all workloads:
- Active Directory / LDAP
- DNS
- NTP
- Backup (NetBackup, Veeam, Commvault)
- Monitoring (Splunk, Datadog, Zabbix, Nagios)
- Patching / SCCM / WSUS
- Anti-virus / EDR management servers

**Why first?**
- Core services represent a large percentage of total traffic
- Rules for them de-clutter the dependency map
- If you ringfence an app without allowing its core service dependencies, you break it
- Core service rules are consistent across workloads — write once, apply broadly

**Illumio Tools**: `identify-infrastructure-services` uses traffic graph analysis to automatically
find core services based on connection patterns (high fan-in = provider infra, high fan-out = consumer infra)

## T — Target Ringfencing for Business Applications

**Goal**: After core services are handled, ringfence your business applications.

Ringfencing = coarse-grained segmentation at the app level:
1. Each app gets a virtual perimeter (ruleset scoped to app+env)
2. Internal communication within the app is allowed (intra-scope rule)
3. Known remote apps get explicit allow rules (extra-scope rules)
4. Unknown traffic is blocked (via deny rules in selective mode, or default-deny in full mode)

**Progressive approach**:
- Start with `dry_run=true` to preview what rules would be created
- Use `skip_allowed=false` to create rules for ALL observed traffic (self-documenting)
- Validate with `enforcement-readiness` before enforcing
- Start with selective enforcement (deny rules block, default=allow)
- Graduate to full enforcement (default=deny) after validation

**Illumio Tools**: `create-ringfence`, `enforcement-readiness`, `get-policy-coverage-report`

## Putting FIRST Together

```
Find metadata  →  Get label data into the PCE
     ↓
Identify labels  →  Design R+A+E+L model
     ↓
Reach out  →  Engage service owners, validate dependency maps
     ↓
Start with core  →  Policy DNS, AD, backup, monitoring first
     ↓
Target ringfencing  →  Ringfence business apps, progressive enforcement
```

Each step builds on the previous one. Skipping steps leads to broken connectivity,
missing policies, and frustrated stakeholders.
"""
    },
    "illumio://methodology/core-services": {
        "name": "Core Services Strategy",
        "description": "Why infrastructure services must be policy'd first — identification, types, and strategy for core service segmentation",
        "content": """# Core Services — Policy Infrastructure First

## What Are Core Services?

Core services are infrastructure services consumed by most or all workloads in your environment.
They provide platform or operating system-level functionality.

**Examples:**
| Service | Protocol/Port | Direction | Why It's Core |
|---------|--------------|-----------|---------------|
| Active Directory / LDAP | 389/636, 88 (Kerberos) | Provider (inbound) | Authentication for all Windows workloads |
| DNS | 53 UDP/TCP | Provider (inbound) | Name resolution for everything |
| NTP | 123 UDP | Provider (inbound) | Time sync, affects logging and auth |
| NetBackup / Veeam | Various | Consumer (outbound) | Backup agents connect to all workloads |
| Splunk / SIEM | 514, 8089, 9997 | Consumer (outbound) | Log collection from all workloads |
| SCCM / WSUS / Patching | 8530, 443 | Provider (inbound) | OS patching for managed workloads |
| Monitoring (Nagios, Zabbix) | Various | Consumer (outbound) | Health checks on all systems |
| Anti-virus mgmt (SEP, CrowdStrike) | Various | Both | Agent management and updates |
| DHCP | 67/68 UDP | Provider | IP assignment |
| Proxy / Web Gateway | 8080, 3128 | Provider (inbound) | Internet access for workloads |

## Why Policy Core Services First?

### 1. They Are a Large Percentage of Traffic
Core service connections often represent 40-60% of total observed traffic.
Policy'ing them first dramatically simplifies the dependency map for application owners.

### 2. They De-Clutter the Dependency Map
Once core service rules exist, application dependency maps show only
application-specific traffic — which is what app owners need to validate.

### 3. Ringfencing Without Core Services Breaks Things
If you ringfence an application but haven't allowed DNS, AD, or monitoring:
- DNS lookups fail → app can't resolve hostnames
- AD auth fails → users can't log in
- Monitoring breaks → false alerts, SLA violations
- Backup stops → data loss risk

**Always** create core service rules before ringfencing business apps.

### 4. Core Service Rules Are Broadly Applicable
A rule like "All workloads can reach DNS on port 53" applies everywhere.
Write it once, and it covers every app you ringfence later.

## Identifying Core Services

### Automatic Detection
Use `identify-infrastructure-services` to find core services automatically.
It analyzes the app-to-app communication graph and scores services:

**Provider Infrastructure** (consumed by many apps):
- High in-degree centrality (many apps connect TO it)
- Low out-degree (doesn't initiate connections to many apps)
- Examples: DNS, AD, NTP, SCCM

**Consumer Infrastructure** (connects out to many apps):
- High out-degree centrality (connects TO many apps)
- Low in-degree (few apps connect to it)
- Examples: Monitoring, backup, log shipping, vulnerability scanners

**Scoring:**
- Provider score: 40% in-degree + 30% consumer ratio + 25% betweenness + 5% volume
- Consumer score: 40% out-degree + 30% producer ratio + 25% betweenness + 5% volume
- Mixed-traffic dampening reduces scores for bidirectional apps (those are business apps, not infra)
- Classification: Core Infrastructure (≥75), Shared Service (≥50), Standard Application (<50)

### Manual Identification
Ask your infrastructure team: "Which services do ALL servers need?"
The answer is your core services list.

## Core Service Policy Strategy

### Step 1: Identify
```
identify-infrastructure-services --env Production --min_flows 100
```

### Step 2: Label
Ensure all core service workloads have correct labels:
- Role: DNS, ActiveDirectory, Backup, Monitoring, etc.
- App: Infrastructure or the specific product name
- Env: Production (core services are almost always production)

### Step 3: Write Allow Rules
Create rulesets with broad scopes that allow core service traffic:
- "All Workloads → DNS on port 53"
- "All Workloads → AD on ports 389, 636, 88"
- "Backup servers → All Workloads on backup agent ports"

### Step 4: Validate
- `get-traffic-flows-summary` confirms traffic is policy-covered
- `get-policy-coverage-report` shows any remaining gaps

### Step 5: Then Ringfence Apps
Now that core services have rules, ringfencing business apps won't break infrastructure dependencies.

## Core Services and Deny Rules
The design guide predates deny/override deny rules. Important additions:

- **DO NOT** ringfence core services with deny rules in most cases
  - Core services need broad accessibility — deny rules restrict that
  - Exception: restrict management ports (SSH/RDP) on core service servers to jump hosts

- **Override deny** may apply to core services in emergency scenarios:
  - Compromised AD server → override deny to isolate it immediately
  - Core service with active vulnerability → override deny to block exploitation
  - These are emergency actions, not normal policy
"""
    },
    "illumio://methodology/ringfencing-patterns": {
        "name": "Ringfencing Patterns & Granularity Levels",
        "description": "Three levels of application segmentation — App Group Level, Role Level All Services, Role Level Specified Services — with deny rule integration",
        "content": """# Ringfencing Patterns — Progressive Granularity

Illumio supports multiple levels of segmentation granularity. You can mix and match
based on each application's security requirements.

## Pattern 1: App Group Level (Application Ringfencing)

**The most common pattern.** A virtual perimeter around the entire application.

```
┌─────────────────────────────────────────┐
│  App=CRM, Env=Production                │
│                                          │
│  ┌─────┐   ┌─────┐   ┌─────┐           │
│  │ Web │←→│ App │←→│ DB  │           │
│  └─────┘   └─────┘   └─────┘           │
│     ↕ All workloads communicate freely   │
└─────────────────────────────────────────┘
     ↑ Only authorized external apps can enter
```

**Rules:**
- Intra-scope: All Workloads → All Workloads on All Services (free internal comms)
- Extra-scope: Specific remote apps → All Workloads on All Services
- In selective mode: Add deny rule blocking all other inbound

**Characteristics:**
- Simple to implement and maintain
- Prevents lateral movement BETWEEN applications
- Does NOT restrict lateral movement WITHIN the application
- Best balance of security vs complexity for most apps
- Most Illumio customers use this as their baseline

## Pattern 2: Role Level — All Services

**Adds role-based restrictions within the application perimeter.**

```
┌──────────────────────────────────────────┐
│  App=CRM, Env=Production                 │
│                                           │
│  ┌─────┐   ┌─────┐   ┌─────┐            │
│  │ Web │──→│ App │──→│ DB  │            │
│  └─────┘   └─────┘   └─────┘            │
│     Web cannot directly reach DB          │
└──────────────────────────────────────────┘
```

**Rules:**
- Role-to-role allow rules: Web → App on All Services, App → DB on All Services
- No direct Web → DB rule (so Web can't reach the database)
- Extra-scope: External apps → specific roles only

**Characteristics:**
- More restrictive than App Group Level
- Prevents lateral movement between tiers within the app
- Still uses All Services — any port is allowed between authorized roles
- Requires knowledge of which roles talk to which

## Pattern 3: Role Level — Specified Services

**The most granular level. Role-to-role, port-by-port.**

```
┌──────────────────────────────────────────┐
│  App=CRM, Env=Production                 │
│                                           │
│  ┌─────┐ 8443  ┌─────┐ 3306  ┌─────┐   │
│  │ Web │──────→│ App │──────→│ DB  │   │
│  └─────┘       └─────┘       └─────┘   │
│     Only specified ports allowed          │
└──────────────────────────────────────────┘
```

**Rules:**
- Web → App on TCP 8443 only
- App → DB on TCP 3306 only
- No other connections allowed within the app

**Characteristics:**
- Highest security — prevents lateral movement even within an app
- Requires detailed knowledge of exact ports/protocols per role
- More maintenance as applications change over time
- Recommended for **Digital Crown Jewels** (sensitive apps)

## Choosing the Right Pattern

| Factor | App Group | Role All Services | Role Specified |
|--------|-----------|-------------------|----------------|
| Security level | Good | Better | Best |
| Complexity | Low | Medium | High |
| Maintenance | Low | Medium | Higher |
| Knowledge needed | App boundaries | Role-to-role flow | Exact ports |
| Best for | Most apps | Important apps | Crown jewels |

**Recommended approach:**
- App Group Level for 80% of applications (baseline protection)
- Role Level All Services for important business apps
- Role Level Specified Services for digital crown jewels (PCI CDE, SWIFT zone, ePHI)
- You can upgrade an app's pattern anytime without changing other apps

## Deny Rules and Ringfencing (Not in Original Design Guide)

The design guide predates Illumio's deny rule feature. Here's how deny rules integrate:

### Standard Ringfencing (Full Enforcement)
- No deny rules needed — full enforcement default is DENY ALL
- Allow rules are sufficient: anything not explicitly allowed is blocked

### Selective Ringfencing (Selective Enforcement)
- Selective mode default is ALLOW ALL — deny rules are required to block traffic
- Add a **regular deny rule** (`override: false`) blocking inbound to the app scope
- Known remote apps get **allow rules** which are processed BEFORE the deny rule
- Processing order: Allow (step 3) → Deny (step 4) → Default allow

### Override Deny — NOT for Ringfencing
Override deny is processed BEFORE allow rules (step 2). If you use it for ringfencing:
- Your extra-scope allow rules for known remote apps will be OVERRIDDEN
- Nothing can get through, including legitimate traffic
- Override deny means "this must not happen under any circumstances"
- Use cases: emergency isolation, hard compliance blocks, active attack response
- NEVER use override deny for routine segmentation

### Deny Consumer Options
When adding deny rules for ringfencing:
- `any` (default): Deny rule enforced only at destination workloads. Safest.
- `ams`: Deny rule pushed to ALL managed workloads. Broader but wider blast radius.
- `ams_and_any`: Both. Maximum enforcement but highest impact.
"""
    },
    "illumio://methodology/crown-jewels": {
        "name": "Digital Crown Jewels",
        "description": "Identifying and protecting your most sensitive applications with the highest level of segmentation control",
        "content": """# Digital Crown Jewels — Maximum Protection

## What Are Digital Crown Jewels?

Crown jewels are applications that store or process your most sensitive data:
- **Payment/financial data** — PCI cardholder data, banking systems, trading platforms
- **Personal information** — PII, PHI (health records), employee data
- **Trade secrets** — intellectual property, source code repositories, R&D systems
- **Critical infrastructure** — industrial control systems, SCADA
- **Regulatory data** — SWIFT messaging systems, SOX financial reporting
- **Authentication systems** — Active Directory, certificate authorities, identity providers

## Why Crown Jewels Need Special Treatment

Most applications can be adequately protected with **App Group Level ringfencing** —
a coarse-grained perimeter around the entire application.

Crown jewels need **Role Level Specified Services** — the most granular pattern:
- Port-by-port, protocol-by-protocol control
- Web → App on TCP 8443 ONLY, App → DB on TCP 3306 ONLY
- No "All Services" rules within the crown jewel perimeter
- This prevents lateral movement WITHIN the application

## Identifying Crown Jewels

### Ask These Questions
1. What data, if breached, would make headlines?
2. What systems, if compromised, would halt business operations?
3. What regulatory frameworks apply, and which systems are in scope?
4. What applications have the highest data sensitivity classification?

### Common Crown Jewels by Industry
| Industry | Crown Jewels |
|----------|-------------|
| Financial Services | Trading platforms, payment processing, SWIFT, core banking |
| Healthcare | EMR/EHR systems, PACS imaging, patient databases |
| Retail | POS systems, payment processing, customer databases |
| Manufacturing | SCADA/ICS, R&D systems, patent databases |
| Technology | Source code repos, CI/CD pipelines, secrets management |
| Government | Classified systems, citizen data, critical infrastructure |

## Crown Jewel Protection Strategy

### Step 1: Identify and Label
- Label crown jewel workloads with specific app and role labels
- Example: App=PaymentGateway, Role=PaymentDB, Env=Production
- Ensure 100% label accuracy — no room for error on critical systems

### Step 2: Map Dependencies
```
get-traffic-flows-summary --app PaymentGateway --env Production
identify-infrastructure-services --app PaymentGateway --env Production
```
- Document every connection, every port, every protocol
- Validate with application owners — "is this expected traffic?"
- Flag any unexpected connections for investigation

### Step 3: Write Granular Rules (Role Level Specified Services)
Instead of "All Workloads → All Workloads on All Services":
- Payment Web → Payment App on TCP 8443
- Payment App → Payment DB on TCP 3306
- Payment App → Payment Cache on TCP 6379
- Monitoring → All Roles on TCP 9100 (metrics)
- Nothing else is allowed within the perimeter

### Step 4: Add Compliance-Specific Controls
For PCI crown jewels:
- Block high-risk ports (RDP, Telnet, FTP) with deny rules
- Override deny for hard compliance blocks ("CDE must never reach internet")
- Encrypt all data-in-transit (block HTTP, require HTTPS)

For SWIFT crown jewels:
- Override deny blocking SWIFT zone → internet
- Restrict admin access (SSH/RDP) to jump hosts only
- Block all unencrypted protocols

### Step 5: Enforce Progressively
1. Visibility Only → collect traffic flows, validate rules
2. Selective → deny rules active, verify no breakage
3. Full enforcement → default=deny, only explicitly allowed traffic flows

### Step 6: Monitor Continuously
```
compliance-check --framework pci-dss --app PaymentGateway --env Production
detect-lateral-movement-paths --app PaymentGateway --env Production
enforcement-readiness --app PaymentGateway --env Production
```

## Crown Jewels and Deny/Override Deny Rules

### Regular Deny Rules for Selective Mode
- Crown jewels in selective mode NEED deny rules for ringfencing
- Block ALL inbound except explicitly allowed sources
- Use the most restrictive deny_consumer option appropriate

### Override Deny for Hard Compliance Blocks
Override deny is appropriate for crown jewels in specific scenarios:
- "PCI CDE must NEVER reach the internet" → override deny
- "SWIFT zone must NEVER have direct internet access" → override deny
- "ePHI database must NEVER be accessible from development" → override deny
- These are absolute blocks that no allow rule should ever bypass

### Override Deny is NOT for Day-to-Day Segmentation
Even for crown jewels, normal segmentation uses regular deny rules + allow rules.
Override deny is the nuclear option — use it only for compliance-mandated hard blocks
and emergency isolation scenarios.

## Maintenance Considerations
Crown jewel protection at Role Level Specified Services requires more maintenance:
- Application changes (new microservice, port change) require rule updates
- Regular reviews with application owners
- `compare-draft-active` to detect policy drift
- Automated compliance checks on a schedule
- The maintenance cost is justified by the data sensitivity
"""
    },
    "illumio://operations/logging-monitoring": {
        "name": "Logging, Monitoring & SIEM Integration",
        "description": "PCE logging types, SIEM integration, traffic data records, auditable events, and alerting strategies",
        "content": """# Logging, Monitoring, and Alerting with Illumio

## Three Types of PCE Log Data

### 1. PCE Internal Messages
- Unstructured log records about PCE component operations
- For support and troubleshooting only
- Managed automatically — log rotation, disk space management
- Stored in PCE log directory (on-premises)
- Not typically exported to SIEM

### 2. Auditable Events
Structured messages about significant security events:
- Agent activated / deactivated
- User password changed
- Security policy modified or provisioned
- Label created / modified / deleted
- Workload paired / unpaired
- Enforcement mode changed

**Properties:**
- Well-defined data fields (structured, parseable)
- Comply with Common Criteria Class FAU Security Audit standard
- Stored in PCE database, queryable via web UI and API
- Can be published to SIEM via syslog or Fluentd
- Available in JSON, CEF, or LEEF formats

**Illumio Tool**: `get-events` provides access to auditable events with severity filtering

### 3. Traffic Data Records
Periodic summaries of connections observed on managed workloads:
- Source and destination (IP, hostname, workload)
- Labels for source and destination (when available)
- Port, protocol, and process information
- Policy decision: **allowed**, **blocked**, or **potentially_blocked**
- Timestamp and volume data

**Traffic record types:**
- **Accepted**: Connections allowed by policy or default action
- **Blocked**: Connections denied by policy enforcement
- **Potentially Blocked**: Connections on non-enforcing workloads that WOULD be blocked if enforced

**Volume warning:** Traffic data can be very high-volume. Ensure your SIEM has sufficient capacity.

## SIEM Integration

### Supported SIEM Products
- **Splunk**: Illumio App for Splunk available on Splunkbase (turnkey integration)
- **HPE ArcSight**: CEF format output
- **IBM QRadar**: LEEF format output
- **Any syslog-compatible SIEM**: JSON, CEF, or LEEF via syslog
- **Fluentd-compatible systems**: Native Fluentd output

### Integration Architecture
```
PCE → syslog/Fluentd → SIEM
  ├── Auditable events (structured)
  └── Traffic data records (high volume)
```

### What to Send to Your SIEM
| Data Type | Volume | Value | Recommended |
|-----------|--------|-------|-------------|
| Auditable events | Low | High | Always export |
| Accepted traffic | High | Medium | Export if capacity allows |
| Blocked traffic | Medium | Very High | Always export |
| Potentially blocked | Medium | High | Export during rollout |

## Alerting Strategies

### Individual Event Alerts
High-priority events to alert on immediately:
- **agent.tampering** — VEN detected unauthorized changes to local firewall rules
- **enforcement_mode_changed** — workload enforcement mode was modified
- **policy_provisioned** — security policy was pushed to active
- **workload.unpaired** — VEN was removed from a managed workload

### Aggregate/Trend Alerts
Monitor totals and trends:
- Total messages per day by type — sudden spikes indicate issues
- Blocked traffic volume increase — may indicate attack or misconfiguration
- New "potentially blocked" flows appearing — policy gaps
- Workload count changes — track VEN deployment progress

### Traffic-Based Alerting
Use traffic data records for security monitoring:
- **Cross-environment traffic**: Production ↔ Development connections (label-enriched flows make this easy)
- **Unexpected protocol usage**: Telnet, FTP on production systems
- **Lateral movement indicators**: New connections between previously unrelated apps
- **Volume anomalies**: Sudden increase in traffic to a specific workload

**Illumio Tools:**
- `detect-lateral-movement-paths` — identifies potential lateral movement vectors
- `find-unmanaged-traffic` — surfaces unknown connections
- `get-traffic-flows-summary` — comprehensive traffic analysis

## Operational Monitoring

### PCE Health (On-Premises)
- Monitor PCE component health via internal messages
- Track PCE cluster state (primary/secondary, replication lag)
- Disk space monitoring for log and database storage

### VEN Health
- Track VEN connectivity status via PCE
- Alert on VEN tamper events
- Monitor VEN version distribution for upgrade tracking

### Policy Health
- `compare-draft-active` — detect uncommitted draft changes
- `enforcement-readiness` — track enforcement rollout progress
- `compliance-check` — periodic compliance validation
- `get-policy-coverage-report` — measure policy completeness

## Traffic Data for Forensics
Traffic data records are invaluable for incident investigation:
- "Which workloads communicated with the compromised server in the last 7 days?"
- "What ports were used for connections crossing from dev to prod?"
- "When did the first unauthorized connection to the database appear?"
- Labels enrich raw flow data with business context — you don't just see IPs, you see applications
"""
    },
}

@server.list_resources()
async def handle_list_resources() -> list[types.Resource]:
    """List Illumio knowledge base resources."""
    resources = []
    for uri, info in ILLUMIO_RESOURCES.items():
        resources.append(types.Resource(
            uri=uri,
            name=info["name"],
            description=info["description"],
            mimeType="text/plain"
        ))
    return resources

@server.read_resource()
async def handle_read_resource(uri) -> str:
    """Read an Illumio knowledge base resource."""
    uri_str = str(uri)
    if uri_str in ILLUMIO_RESOURCES:
        return ILLUMIO_RESOURCES[uri_str]["content"]
    raise ValueError(f"Unknown resource: {uri_str}")

@server.list_prompts()
async def handle_list_prompts() -> list[types.Prompt]:
    """
    List available prompts.
        Each prompt can have optional arguments to customize its behavior.
    """
    return [
        types.Prompt(
            name="ringfence-application",
            description="Ringfence an application by deploying rulesets to limit the inbound and outbound traffic",
            arguments=[
                types.PromptArgument(
                    name="application_name",
                    description="Name of the application to ringfence",
                    required=True,
                ),
                types.PromptArgument(
                    name="application_environment",
                    description="Environment of the application to ringfence",
                    required=True,
                )
            ],
        ),
        types.Prompt(
            name="analyze-application-traffic",
            description="Analyze the traffic flows for an application and environment",
            arguments=[
                types.PromptArgument(
                    name="application_name",
                    description="Name of the application to analyze",
                    required=True,
                ),
                types.PromptArgument(
                    name="application_environment",
                    description="Environment of the application to analyze",
                    required=True,
                )
            ]
        ),
        types.Prompt(
            name="emergency-isolate-application",
            description="Emergency isolation of an application using override deny rules — blocks ALL traffic to/from the app immediately, overriding any existing allow rules. Use only for security incidents.",
            arguments=[
                types.PromptArgument(
                    name="application_name",
                    description="Name of the application to isolate",
                    required=True,
                ),
                types.PromptArgument(
                    name="application_environment",
                    description="Environment of the application to isolate",
                    required=True,
                )
            ]
        )
    ]

@server.get_prompt()
async def handle_get_prompt(
    name: str, arguments: dict[str, str] | None
) -> types.GetPromptResult:
    """
    Generate a prompt by combining arguments with server state.
    The prompt includes all current notes and can be customized via arguments.
    """
    if name == "ringfence-application":
        return types.GetPromptResult(
            description="Ringfence an application by deploying rulesets to limit the inbound and outbound traffic",
        messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(
                        type="text",
                        text=f"""
Ringfence the application {arguments['application_name']} in the environment {arguments['application_environment']}.
Always reference labels as hrefs like /orgs/1/labels/57 or similar.
Consumers means the source of the traffic, providers means the destination of the traffic.

1. First, get all the labels to have them available for later use.
2. Retrieve all the traffic flows inside the application and environment. 
   Only fetch potentially blocked or blocked traffic.Analyze the connections.
3. Then retrieve all the traffic flows inbound to the application and environment.
4. Inside the app, please be sure to have rules for each role or app tier to connect to the other tiers. 
5. Prefer the traffic summary over the traffic flow tool.

Always use traffic flows to find out what other applications and environemnts need to connect into {arguments['application_name']}, 
and then deploy rulesets to limit the inbound traffic to those applications and environments. 
For traffic that is required to connect outbound from {arguments['application_name']}, deploy rulesets to limit the 
outbound traffic to those applications and environments. If a consumer is coming from the same app and env, please use 
all workloads for the rules inside the scope (intra-scope). If it comes from the outside, please use app, env and if possible role

If a remote app is connected as destination, a new ruleset needs to be created that has the name of the remote app and env,
all incoming connections need to be added as extra-scope rules in that ruleset.
Always use hrefs for labels and workloads.
The logic in illumio is the following:

If a scope exists. Rules define connections within the scope if unscoped consumers is not set to true. Unscoped consumers define inbound traffic from things outside the scope. The unscoped consumer is a set of labels being the source of inbound traffic. Provider is the destination. For the provider a value of AMS (short for all workloads) means that a connection is allowed for all workloads inside the scope. So for example if the source is role=monitoring, app=nagios, env=prod, then the rule for the app=ordering, env=prod application would be:

  consumer: role=monitoring,app=nagios,env=prod 
  provider: role=All workloads
  service: 5666/tcp

  If a rule is setting unscoped consumers to "false", this means that the rule is intra scope. Repeating any label that is in the scope does not make sense for this. Instead use role or whatever specific label to characterize the thing in the scope.

e.g. for the loadbalancer to connect to the web-tier in ordering, prod the rule is:

scope: app=ordering, env=prod
consumers: role=loadbalancer
providers: role=web
service: 8080/tcp
unscoped consumers: false

This is a intra-scope rule allowing the role=loadbalancer,app=ordering,env=prod workloads to connect to the role=web,app=ordering,env=prod workloads on port 8080/tcp. 

For traffic that goes from the {arguments['application_name']} app to the outside, please create a ruleset with the name {arguments['application_name']}-outbound and make it scopeless.
Add all the outbound traffic to that ruleset using roles, applications and environments as labels.
                        """
                    )
                )
            ]
        )
    elif name == "analyze-application-traffic":
        return types.GetPromptResult(
            description="Analyze the traffic flows for an application and environment",
            messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(
                        type="text",
                        text=f"""
                            Please provide the traffic flows for {arguments['application_name']} in the environment {arguments['application_environment']}.
                            Order by inbound and outbound traffic and app/env/role tupels.
                            Find other label types that are of interest and show them. Display your results in a react component. Show protocol, port and try to
                            understand the traffic flows (e.g. 5666/tcp likely could be nagios).
                            Categorize traffic into infrastructure and application traffic.
                            Find out if the application is internet facing or not.
                            Show illumio role labels, as well as application and environment labels in the output.
                        """
                    )
                )
            ]
        )

    elif name == "emergency-isolate-application":
        return types.GetPromptResult(
            description="Emergency isolation of an application using override deny rules",
            messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(
                        type="text",
                        text=f"""
EMERGENCY ISOLATION: Immediately isolate application {arguments['application_name']} in environment {arguments['application_environment']}.

This is a security incident response action. You MUST use OVERRIDE DENY rules — these are the highest priority deny rules
in Illumio that block traffic even when allow rules exist. This is the correct and ONLY use case for override deny.

IMPORTANT CONTEXT — Illumio Rule Processing Order:
1. Essential rules (built-in)
2. **Override Deny rules** — THIS IS WHAT WE USE HERE. Blocks traffic above ALL allow rules.
3. Allow rules — these CANNOT override our override deny
4. Regular deny rules — NOT sufficient for emergency isolation (allow rules are processed first)
5. Default action

Steps:
1. First, get the labels for app={arguments['application_name']} and env={arguments['application_environment']} to get their hrefs.
2. Find or create a ruleset scoped to this app+env (name it "EMERGENCY-ISOLATE-{arguments['application_name']}-{arguments['application_environment']}").
3. Create an OVERRIDE DENY rule (override_deny=true) that blocks ALL inbound traffic:
   - providers: All Workloads (ams)
   - consumers: All Workloads (ams) AND IP list Any (0.0.0.0/0)
   - ingress_services: All Services
   - unscoped_consumers: true
   - override_deny: true  ← CRITICAL: this makes it override deny, not regular deny
4. Optionally create a second override deny rule for outbound if full isolation is needed.
5. PROVISION the policy immediately using provision-policy so it takes effect.
6. Report what was created and confirm the application is now isolated.

WARNING: Override deny rules override ALL allow rules. This WILL break all connectivity to/from this application.
Only use this for genuine security incidents. To undo, delete the override deny rules and re-provision.
                        """
                    )
                )
            ]
        )

    else:
        raise ValueError(f"Unknown prompt: {name}")

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """
    List available tools.
    Each tool specifies its arguments using JSON Schema validation.
    """
    return [
        types.Tool(
            name="get-workloads",
            description="Get workloads from the PCE with optional filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Filter by workload name (supports partial matches)"},
                    "hostname": {"type": "string", "description": "Filter by hostname (supports partial matches)"},
                    "ip_address": {"type": "string", "description": "Filter by IP address (supports partial matches)"},
                    "description": {"type": "string", "description": "Filter by description (supports partial matches)"},
                    "managed": {"type": "boolean", "description": "Filter managed (true) or unmanaged (false) workloads"},
                    "online": {"type": "boolean", "description": "Filter online (true) or offline (false) workloads"},
                    "enforcement_mode": {
                        "type": "string",
                        "enum": ["visibility_only", "full", "idle", "selective"],
                        "description": "Filter by enforcement mode"
                    },
                    "labels": {"type": "string", "description": "JSON-encoded list of label URIs to filter by"},
                    "max_results": {"type": "integer", "description": "Maximum number of workloads to return (default 10000)"},
                },
            },
        ),
        types.Tool(
            name="update-workload",
            description="Update a workload in the PCE. Identify by href (preferred) or name. Provide only fields you want to change.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {"type": "string", "description": "Workload href (e.g., /orgs/1/workloads/xxxx). Preferred identifier."},
                    "name": {"type": "string", "description": "Workload name to find (alternative to href). If updating, this finds the workload."},
                    "new_name": {"type": "string", "description": "New name for the workload"},
                    "description": {"type": "string", "description": "New description for the workload"},
                    "hostname": {"type": "string", "description": "New hostname for the workload"},
                    "enforcement_mode": {
                        "type": "string",
                        "enum": ["visibility_only", "full", "idle", "selective"],
                        "description": "Enforcement mode to set"
                    },
                    "ip_addresses": {"type": "array", "items": {"type": "string"}, "description": "New IP addresses (replaces existing interfaces)"},
                    "labels": {
                        "type": "array",
                        "items": {"type": "object", "properties": {"key": {"type": "string"}, "value": {"type": "string"}}},
                        "description": "Labels to assign (replaces existing labels). Each item has 'key' and 'value'."
                    },
                },
            }
        ),
        types.Tool(
            name="get-labels",
            description="Get labels from the PCE with optional filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "Filter by label key/type (e.g., 'role', 'app', 'env', 'loc')"},
                    "value": {"type": "string", "description": "Filter by label value (supports partial matches)"},
                    "max_results": {"type": "integer", "description": "Maximum number of labels to return"},
                    "include_deleted": {"type": "boolean", "description": "Include deleted labels"},
                    "usage": {"type": "boolean", "description": "Include label usage flags"},
                },
            }
        ),
        types.Tool(
            name="create-workload",
            description="Create a Illumio Core unmanaged workload in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "ip_addresses": {"type": "array", "items": {"type": "string"}},
                    "labels": {"type": "array", "items":
                               {"type": "object", "properties": {"key": {"type": "string"}, "value": {"type": "string"}}}
                    },
                },
                "required": ["name", "ip_addresses"],
            }
        ),
        types.Tool(
            name="create-label",
            description="Create a label of a specific type and the value in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                    "value": {"type": "string"},
                },
                "required": ["key", "value"]
            }
        ),
        types.Tool(
            name="delete-label",
            description="Delete a label in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                    "value": {"type": "string"},
                },
                "required": ["key", "value"]
            }
        ),
        types.Tool(
            name="delete-workload",
            description="Delete a workload from the PCE. Identify by href (preferred) or name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {"type": "string", "description": "Workload href (e.g., /orgs/1/workloads/xxxx)"},
                    "name": {"type": "string", "description": "Workload name (alternative to href)"},
                },
            }
        ),
        types.Tool(
            name="get-traffic-flows",
            description="Get traffic flows from the PCE with comprehensive filtering options",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_date": {"type": "string", "description": "Starting datetime (YYYY-MM-DD or timestamp)"},
                    "end_date": {"type": "string", "description": "Ending datetime (YYYY-MM-DD or timestamp)"},
                    "include_sources": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Sources to include (label/IP list/workload HREFs, FQDNs, IPs)"
                    },
                    "exclude_sources": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Sources to exclude (label/IP list/workload HREFs, FQDNs, IPs)"
                    },
                    "include_destinations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Destinations to include (label/IP list/workload HREFs, FQDNs, IPs)"
                    },
                    "exclude_destinations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Destinations to exclude (label/IP list/workload HREFs, FQDNs, IPs)"
                    },
                    "include_services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "proto": {"type": "string"}
                            }
                        }
                    },
                    "exclude_services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "proto": {"type": "string"}
                            }
                        }
                    },
                    "policy_decisions": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["allowed", "blocked", "potentially_blocked", "unknown"]
                        }
                    },
                    "exclude_workloads_from_ip_list_query": {"type": "boolean"},
                    "max_results": {"type": "integer"},
                    "query_name": {"type": "string"}
                },
                "required": ["start_date", "end_date"]
            }
        ),
        types.Tool(
            name="get-traffic-flows-summary",
            description="Get traffic flows from the PCE in a summarized text format, this is a text format that is not a dataframe, it also is not json, the form is: 'From <source> to <destination> on <port> <proto>: <number of connections>'",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_date": {"type": "string", "description": "Starting datetime (YYYY-MM-DD or timestamp)"},
                    "end_date": {"type": "string", "description": "Ending datetime (YYYY-MM-DD or timestamp)"},
                    "include_sources": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Sources to include (label/IP list/workload HREFs, FQDNs, IPs). Best case these are hrefs like /orgs/1/labels/57 or similar. Other way is app=env as an example (label key and value)"
                    },
                    "exclude_sources": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Sources to exclude (label/IP list/workload HREFs, FQDNs, IPs). Best case these are hrefs like /orgs/1/labels/57 or similar. Other way is app=env as an example (label key and value)"
                    },
                    "include_destinations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Destinations to include (label/IP list/workload HREFs, FQDNs, IPs). Best case these are hrefs like /orgs/1/labels/57 or similar. Other way is app=env as an example (label key and value)"
                    },
                    "exclude_destinations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Destinations to exclude (label/IP list/workload HREFs, FQDNs, IPs). Best case these are hrefs like /orgs/1/labels/57 or similar. Other way is app=env as an example (label key and value)"
                    },
                    "include_services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "proto": {"type": "string"}
                            }
                        }
                    },
                    "exclude_services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "proto": {"type": "string"}
                            }
                        }
                    },
                    "policy_decisions": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["allowed", "potentially_blocked", "blocked", "unknown"]
                        }
                    },
                    "exclude_workloads_from_ip_list_query": {"type": "boolean"},
                    "max_results": {"type": "integer"},
                    "query_name": {"type": "string"}
                },
                "required": ["start_date", "end_date"]
            }
        ),
        types.Tool(
            name="check-pce-connection",
            description="Are my credentials and the connection to the PCE working?",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        types.Tool(
            name="get-rulesets",
            description="Get rulesets from the PCE with optional filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Filter rulesets by name (supports partial matches)"},
                    "description": {"type": "string", "description": "Filter rulesets by description (supports partial matches)"},
                    "enabled": {"type": "boolean", "description": "Filter by enabled/disabled status"},
                    "labels": {"type": "string", "description": "JSON-encoded list of label URIs to filter by scope"},
                    "max_results": {"type": "integer", "description": "Maximum number of rulesets to return"},
                }
            }
        ),
        types.Tool(
            name="get-iplists",
            description="Get IP lists from the PCE with optional filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Filter IP lists by name (supports partial matches)"},
                    "description": {"type": "string", "description": "Filter by description (supports partial matches)"},
                    "fqdn": {"type": "string", "description": "Filter by FQDN (supports partial matches)"},
                    "ip_address": {"type": "string", "description": "Filter by IP address (supports partial matches)"},
                    "max_results": {"type": "integer", "description": "Maximum number of IP lists to return"},
                }
            }
        ),
        types.Tool(
            name="get-events",
            description="Get events from the PCE with optional filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "event_type": {"type": "string", "description": "Filter by event type (e.g., 'system_task.expire_service_account_api_keys')"},
                    "severity": {
                        "type": "string",
                        "enum": ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"],
                        "description": "Filter by event severity"
                    },
                    "status": {
                        "type": "string",
                        "enum": ["success", "failure"],
                        "description": "Filter by event status"
                    },
                    "created_by": {"type": "string", "description": "Filter by creator (user, agent, or system)"},
                    "timestamp_gte": {"type": "string", "description": "Earliest event timestamp (RFC 3339 format)"},
                    "timestamp_lte": {"type": "string", "description": "Latest event timestamp (RFC 3339 format)"},
                    "max_results": {"type": "integer", "description": "Maximum number of events to return", "default": 100},
                }
            }
        ),
        types.Tool(
            name="create-ruleset",
            description="Create a ruleset in the PCE with support for ring-fencing patterns",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Name of the ruleset (e.g., 'RS-ELK'). Must be unique in the PCE."},
                    "description": {"type": "string", "description": "Description of the ruleset (optional)"},
                    "scopes": {
                        "type": "array",
                        "items": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "description": "List of label combinations that define scopes. Each scope is an array of label values. This need to be label references like /orgs/1/labels/57 or similar. Get the label href from the get-labels tool."
                    },
                    "rules": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "providers": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Array of provider labels, 'ams' for all workloads, or IP list references (e.g., 'iplist:Any (0.0.0.0/0)')"
                                },
                                "consumers": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Array of consumer labels, 'ams' for all workloads, or IP list references (e.g., 'iplist:Any (0.0.0.0/0)')"
                                },
                                "ingress_services": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "port": {"type": "integer"},
                                            "proto": {"type": "string"}
                                        },
                                        "required": ["port", "proto"]
                                    }
                                },
                                "unscoped_consumers": {
                                    "type": "boolean",
                                    "description": "Whether to allow unscoped consumers (extra-scope rule)",
                                    "default": False
                                },
                                "rule_type": {
                                    "type": "string",
                                    "enum": ["allow", "deny", "override_deny"],
                                    "description": "Type of rule: 'allow' (default), 'deny' to block specific traffic, or 'override_deny' to block traffic overriding ALL allow rules (emergency use only — highest priority deny)",
                                    "default": "allow"
                                }
                            },
                            "required": ["providers", "consumers", "ingress_services"]
                        }
                    }
                },
                "required": ["name", "scopes"]
            }
        ),
        types.Tool(
            name="create-deny-rule",
            description="Create a deny rule in an existing ruleset. Deny rules block specific traffic (processed after allow rules). Override deny rules (override_deny=true) are the HIGHEST priority — they block traffic even when allow rules exist, meaning 'this must not happen under any circumstances.' Use override deny for emergency isolation, hard compliance blocks, or active attack response — NOT for normal segmentation or ringfencing. Rule processing order: 1) Essential rules, 2) Override Deny (blocks above all), 3) Allow rules, 4) Deny rules, 5) Default action.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ruleset_href": {
                        "type": "string",
                        "description": "Href of the ruleset to add the deny rule to (e.g., /orgs/1/sec_policy/draft/rule_sets/123)"
                    },
                    "ruleset_name": {
                        "type": "string",
                        "description": "Name of the ruleset to add the deny rule to (alternative to ruleset_href)"
                    },
                    "providers": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Array of provider (destination) references: 'ams' for all workloads, label hrefs, key=value pairs, or 'iplist:<name>'"
                    },
                    "consumers": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Array of consumer (source) references: 'ams' for all workloads, label hrefs, key=value pairs, or 'iplist:<name>'"
                    },
                    "ingress_services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "proto": {"type": "string"}
                            },
                            "required": ["port", "proto"]
                        },
                        "description": "Services to deny (e.g., [{'port': 3389, 'proto': 'tcp'}])"
                    },
                    "override_deny": {
                        "type": "boolean",
                        "description": "If true, creates an override deny rule — the highest priority deny that blocks traffic even if allow rules exist. Means 'this must not happen under any circumstances.' Use for emergency isolation, hard compliance blocks (e.g., PCI zones), or active attack response. If false (default), creates a regular deny rule (processed after allow rules).",
                        "default": False
                    },
                    "unscoped_consumers": {
                        "type": "boolean",
                        "description": "Whether to allow unscoped consumers (extra-scope rule)",
                        "default": False
                    }
                },
                "required": ["providers", "consumers", "ingress_services"]
            }
        ),
        types.Tool(
            name="get-services",
            description="Get services from the PCE with optional filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Filter services by name (supports partial matches)"},
                    "description": {"type": "string", "description": "Filter services by description (supports partial matches)"},
                    "port": {"type": "integer", "description": "Filter services by port number"},
                    "proto": {"type": "string", "description": "Filter services by protocol (e.g., tcp, udp)"},
                    "process_name": {"type": "string", "description": "Filter services by process name"},
                    "max_results": {"type": "integer", "description": "Maximum number of services to return"},
                }
            }
        ),
        types.Tool(
            name="create-service",
            description="Create a new service definition in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Name of the service"},
                    "description": {"type": "string", "description": "Description of the service"},
                    "service_ports": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer", "description": "Port number (-1 for all ports)"},
                                "to_port": {"type": "integer", "description": "End port for a port range (optional)"},
                                "proto": {"type": "integer", "description": "Protocol number (6=TCP, 17=UDP, 1=ICMP)"}
                            },
                            "required": ["proto"]
                        },
                        "description": "Array of port/protocol definitions"
                    },
                },
                "required": ["name", "service_ports"]
            }
        ),
        types.Tool(
            name="update-service",
            description="Update an existing service in the PCE. Identify by href (preferred) or name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {"type": "string", "description": "Service href (e.g., /orgs/1/sec_policy/draft/services/123)"},
                    "name": {"type": "string", "description": "Service name to find (alternative to href)"},
                    "new_name": {"type": "string", "description": "New name for the service"},
                    "description": {"type": "string", "description": "New description"},
                    "service_ports": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "to_port": {"type": "integer"},
                                "proto": {"type": "integer"}
                            },
                            "required": ["proto"]
                        },
                        "description": "New port/protocol definitions (replaces existing)"
                    },
                },
            }
        ),
        types.Tool(
            name="delete-service",
            description="Delete a service from the PCE. Identify by href (preferred) or name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {"type": "string", "description": "Service href (e.g., /orgs/1/sec_policy/draft/services/123)"},
                    "name": {"type": "string", "description": "Service name (alternative to href)"},
                },
            }
        ),
        types.Tool(
            name="update-deny-rule",
            description="Update an existing deny rule in a ruleset. Identify the rule by its href.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {"type": "string", "description": "Deny rule href (e.g., /orgs/1/sec_policy/draft/rule_sets/123/deny_rules/456)"},
                    "enabled": {"type": "boolean", "description": "Enable or disable the deny rule"},
                    "providers": {
                        "type": "array", "items": {"type": "string"},
                        "description": "Updated provider references: 'ams', label hrefs, key=value pairs, or 'iplist:<name>'"
                    },
                    "consumers": {
                        "type": "array", "items": {"type": "string"},
                        "description": "Updated consumer references: 'ams', label hrefs, key=value pairs, or 'iplist:<name>'"
                    },
                    "ingress_services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {"port": {"type": "integer"}, "proto": {"type": "string"}},
                            "required": ["port", "proto"]
                        },
                        "description": "Updated services"
                    },
                },
                "required": ["href"]
            }
        ),
        types.Tool(
            name="delete-deny-rule",
            description="Delete a deny rule from a ruleset by its href",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {"type": "string", "description": "Deny rule href (e.g., /orgs/1/sec_policy/draft/rule_sets/123/deny_rules/456)"},
                },
                "required": ["href"]
            }
        ),
        types.Tool(
            name="update-label",
            description="Update an existing label in the PCE. Provide either: 1) href + new_value (optionally with key), or 2) key + value + new_value to identify and update the label.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Label href (e.g., /orgs/1/labels/42). Use this to directly identify the label."
                    },
                    "key": {
                        "type": "string",
                        "description": "Label type (e.g., role, app, env, loc). Required when using value to identify label, or when using href."
                    },
                    "value": {
                        "type": "string",
                        "description": "Current value of the label. Used with key to identify the label when href is not provided."
                    },
                    "new_value": {
                        "type": "string",
                        "description": "New value for the label. Always required."
                    }
                }
            }
        ),
        types.Tool(
            name="create-iplist",
            description="Create a new IP List in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Name of the IP List"
                    },
                    "description": {
                        "type": "string",
                        "description": "Description of the IP List"
                    },
                    "ip_ranges": {
                        "type": "array",
                        "description": "List of IP ranges to include",
                        "items": {
                            "type": "object",
                            "properties": {
                                "from_ip": {
                                    "type": "string",
                                    "description": "Starting IP address (IPv4 or IPv6)"
                                },
                                "to_ip": {
                                    "type": "string",
                                    "description": "Ending IP address (optional, for ranges)"
                                },
                                "description": {
                                    "type": "string",
                                    "description": "Description of this IP range (optional)"
                                },
                                "exclusion": {
                                    "type": "boolean",
                                    "description": "Whether this is an exclusion range",
                                    "default": False
                                }
                            },
                            "required": ["from_ip"]
                        }
                    },
                    "fqdn": {
                        "type": "string",
                        "description": "Fully Qualified Domain Name (optional)"
                    }
                },
                "required": ["name", "ip_ranges"]
            }
        ),
        types.Tool(
            name="update-iplist",
            description="Update an existing IP List in the PCE. Provide either 'href' or 'name' (but not both) to identify the IP List.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Href of the IP List to update (e.g., /orgs/1/sec_policy/draft/ip_lists/123)"
                    },
                    "name": {
                        "type": "string",
                        "description": "Name of the IP List to update (alternative to href)"
                    },
                    "description": {
                        "type": "string",
                        "description": "New description for the IP List (optional)"
                    },
                    "ip_ranges": {
                        "type": "array",
                        "description": "New list of IP ranges",
                        "items": {
                            "type": "object",
                            "properties": {
                                "from_ip": {
                                    "type": "string",
                                    "description": "Starting IP address (IPv4 or IPv6)"
                                },
                                "to_ip": {
                                    "type": "string",
                                    "description": "Ending IP address (optional, for ranges)"
                                },
                                "description": {
                                    "type": "string",
                                    "description": "Description of this IP range (optional)"
                                },
                                "exclusion": {
                                    "type": "boolean",
                                    "description": "Whether this is an exclusion range",
                                    "default": False
                                }
                            },
                            "required": ["from_ip"]
                        }
                    },
                    "fqdn": {
                        "type": "string",
                        "description": "New Fully Qualified Domain Name (optional)"
                    }
                }
            }
        ),
        types.Tool(
            name="delete-iplist",
            description="Delete an IP List from the PCE. Provide either 'href' or 'name' (but not both) to identify the IP List.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Href of the IP List to delete (e.g., /orgs/1/sec_policy/draft/ip_lists/123)"
                    },
                    "name": {
                        "type": "string",
                        "description": "Name of the IP List to delete (alternative to href)"
                    }
                }
            }
        ),
        types.Tool(
            name="update-ruleset",
            description="Update an existing ruleset in the PCE. Provide either 'href' or 'name' (but not both) to identify the ruleset.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Href of the ruleset to update (e.g., /orgs/1/sec_policy/active/rule_sets/123)"
                    },
                    "name": {
                        "type": "string",
                        "description": "Name of the ruleset to update (alternative to href)"
                    },
                    "description": {
                        "type": "string",
                        "description": "New description for the ruleset"
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "Whether the ruleset is enabled"
                    },
                    "scopes": {
                        "type": "array",
                        "description": "New scopes for the ruleset. Each scope is an array of label identifiers (either href strings like '/orgs/1/labels/42', or key=value strings like 'role=web', or objects with href property).",
                        "items": {
                            "type": "array",
                            "items": {
                                "description": "Label identifier - can be a string (href or key=value) or an object with href property"
                            }
                        }
                    }
                }
            }
        ),
        types.Tool(
            name="delete-ruleset",
            description="Delete a ruleset from the PCE by its href",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Href of the ruleset to delete (e.g., /orgs/1/sec_policy/draft/rule_sets/123)"
                    }
                },
                "required": ["href"]
            }
        ),
        types.Tool(
            name="create-ringfence",
            description="""Create a ringfencing policy for an application. This analyzes traffic flows to discover
which other apps communicate with this app, then creates a ruleset with:
1) An intra-scope rule allowing all workloads within the app to communicate on All Services
2) Extra-scope rules for each remote app+env discovered in traffic, allowing them in on All Services
The result is a coarse-grained segmentation that controls which apps can talk to each other,
reducing risk without requiring per-port policies.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "app_name": {
                        "type": "string",
                        "description": "Application label value (e.g., 'CRM', 'Ordering', 'ELK')"
                    },
                    "env_name": {
                        "type": "string",
                        "description": "Environment label value (e.g., 'Production', 'Staging', 'Development')"
                    },
                    "lookback_days": {
                        "type": "integer",
                        "description": "Number of days to look back for traffic flows (default: 30)",
                        "default": 30
                    },
                    "ruleset_name": {
                        "type": "string",
                        "description": "Custom name for the ringfence ruleset (default: 'RF-<app_name>-<env_name>')"
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "If true, analyze traffic and report what would be created without actually creating anything (default: false)",
                        "default": False
                    },
                    "selective": {
                        "type": "boolean",
                        "description": "If true, adds a deny rule blocking all inbound traffic to the app. "
                            "In selective enforcement mode the default action is allow-all, so without "
                            "this deny rule the ringfence has no teeth. Allow rules for known remote apps "
                            "are processed before the deny rule (rule order: override_deny > allow > deny > default), "
                            "so known apps pass through and everything else hits the deny. "
                            "This gets you to enforcement faster than full enforcement mode.",
                        "default": False
                    },
                    "skip_allowed": {
                        "type": "boolean",
                        "description": "If true, skip creating rules for remote apps whose traffic is already "
                            "fully allowed by existing policy. Default is false, meaning rules are created "
                            "for all observed traffic regardless of policy decision. This makes the ringfence "
                            "ruleset self-documenting — it shows the complete picture of app connectivity. "
                            "Set to true for minimal rulesets that only fill policy gaps.",
                        "default": False
                    },
                    "deny_consumer": {
                        "type": "string",
                        "enum": ["any", "ams", "ams_and_any"],
                        "description": "Controls which consumers the deny rule targets (only used with selective=true). "
                            "Illumio pushes deny rules to the source workload, so this choice matters: "
                            "'any' (default) = IP list Any (0.0.0.0/0) as consumer, deny rule only written to "
                            "destination workloads inside the scope. Safest, no impact on remote workloads. "
                            "'ams' = All Workloads as consumer, deny rule pushed to every managed workload "
                            "outside the scope. Broader enforcement but wider blast radius. "
                            "'ams_and_any' = both All Workloads and Any IP list, maximum coverage for "
                            "managed and unmanaged sources.",
                        "default": "any"
                    }
                },
                "required": ["app_name", "env_name"]
            }
        ),
        types.Tool(
            name="identify-infrastructure-services",
            description="""Analyze traffic flows to identify infrastructure services in your environment.
Builds an app-to-app communication graph and computes centrality metrics to rank apps by how
'infrastructure-like' they are. Infrastructure services (DNS, AD, logging, monitoring platforms,
shared databases) are consumed by many apps and should be policy'd first during segmentation
rollouts. Returns a ranked list with scores, classification tiers, and connectivity details.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "lookback_days": {
                        "type": "integer",
                        "description": "Number of days to look back for traffic flows (default: 90)",
                        "default": 90
                    },
                    "min_connections": {
                        "type": "integer",
                        "description": "Minimum total connections for an edge to be included — filters noise (default: 1)",
                        "default": 1
                    },
                    "top_n": {
                        "type": "integer",
                        "description": "Number of top results to return (default: 20)",
                        "default": 20
                    }
                },
                "required": []
            }
        ),
        types.Tool(
            name="provision-policy",
            description="Provision pending draft policy changes in the PCE. This moves draft rulesets, rules, IP lists, services, and label groups from draft to active state. You can provision all pending changes or specific items by href.",
            inputSchema={
                "type": "object",
                "properties": {
                    "hrefs": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of specific draft hrefs to provision (e.g., ['/orgs/1/sec_policy/draft/rule_sets/123']). If omitted, provisions ALL pending changes."
                    },
                    "change_description": {
                        "type": "string",
                        "description": "Description of the provisioning change (for audit trail)"
                    }
                },
            }
        ),
        types.Tool(
            name="compare-draft-active",
            description="Compare draft vs active policy to see what would change on provisioning. Shows new, modified, and deleted rulesets, rules, IP lists, and services.",
            inputSchema={
                "type": "object",
                "properties": {
                    "resource_type": {
                        "type": "string",
                        "enum": ["rule_sets", "ip_lists", "services", "all"],
                        "description": "Type of resource to compare (default: all)",
                        "default": "all"
                    }
                },
            }
        ),
        types.Tool(
            name="enforcement-readiness",
            description="Assess whether an application is ready for enforcement by analyzing its traffic flows, existing policy coverage, and identifying potential gaps. Provides a readiness score and actionable recommendations.",
            inputSchema={
                "type": "object",
                "properties": {
                    "app_name": {
                        "type": "string",
                        "description": "Application label value (e.g., 'CRM', 'Ordering')"
                    },
                    "env_name": {
                        "type": "string",
                        "description": "Environment label value (e.g., 'Production', 'Staging')"
                    },
                    "lookback_days": {
                        "type": "integer",
                        "description": "Number of days to look back for traffic flows (default: 30)",
                        "default": 30
                    }
                },
                "required": ["app_name", "env_name"]
            }
        ),
        types.Tool(
            name="ringfence-batch",
            description="Create ringfence policies for multiple applications at once. Optionally auto-discovers infrastructure services and ringfences them first, then standard apps. Uses the same logic as create-ringfence for each app.",
            inputSchema={
                "type": "object",
                "properties": {
                    "apps": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "app_name": {"type": "string"},
                                "env_name": {"type": "string"},
                                "selective": {"type": "boolean", "default": False}
                            },
                            "required": ["app_name", "env_name"]
                        },
                        "description": "List of applications to ringfence"
                    },
                    "auto_order": {
                        "type": "boolean",
                        "description": "If true, uses identify-infrastructure-services to order apps by infrastructure score (infra first). Default: false",
                        "default": False
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "If true, preview what would be created without making changes",
                        "default": False
                    },
                    "lookback_days": {
                        "type": "integer",
                        "description": "Number of days to look back for traffic flows (default: 30)",
                        "default": 30
                    }
                },
                "required": ["apps"]
            }
        ),
        types.Tool(
            name="get-workload-enforcement-status",
            description="Get enforcement mode status across all workloads, grouped by application and environment. Shows counts per enforcement mode and identifies apps with mixed enforcement states.",
            inputSchema={
                "type": "object",
                "properties": {
                    "app_name": {
                        "type": "string",
                        "description": "Filter by application name (optional)"
                    },
                    "env_name": {
                        "type": "string",
                        "description": "Filter by environment name (optional)"
                    }
                },
            }
        ),
        types.Tool(
            name="get-policy-coverage-report",
            description="Generate a policy coverage report for an app, showing what traffic is covered by existing rules vs what would be blocked. Helps understand how much of an app's traffic is already policy'd.",
            inputSchema={
                "type": "object",
                "properties": {
                    "app_name": {
                        "type": "string",
                        "description": "Application label value"
                    },
                    "env_name": {
                        "type": "string",
                        "description": "Environment label value"
                    },
                    "lookback_days": {
                        "type": "integer",
                        "description": "Number of days to look back for traffic flows (default: 30)",
                        "default": 30
                    }
                },
                "required": ["app_name", "env_name"]
            }
        ),
        types.Tool(
            name="find-unmanaged-traffic",
            description="Find traffic involving unmanaged (unlabeled) workloads or IP addresses. These are sources or destinations without app/env labels, representing potential policy blind spots.",
            inputSchema={
                "type": "object",
                "properties": {
                    "lookback_days": {
                        "type": "integer",
                        "description": "Number of days to look back (default: 30)",
                        "default": 30
                    },
                    "direction": {
                        "type": "string",
                        "enum": ["inbound", "outbound", "both"],
                        "description": "Filter by traffic direction relative to managed workloads (default: both)",
                        "default": "both"
                    },
                    "min_connections": {
                        "type": "integer",
                        "description": "Minimum connections to include (filters noise, default: 1)",
                        "default": 1
                    },
                    "top_n": {
                        "type": "integer",
                        "description": "Number of top results to return (default: 50)",
                        "default": 50
                    }
                },
            }
        ),
        types.Tool(
            name="detect-lateral-movement-paths",
            description="Analyze traffic patterns to detect potential lateral movement paths — chains of connections that could allow an attacker to pivot between applications. Identifies apps that serve as bridges between otherwise disconnected app groups.",
            inputSchema={
                "type": "object",
                "properties": {
                    "app_name": {
                        "type": "string",
                        "description": "Starting application to analyze paths from (optional — if omitted, analyzes all apps)"
                    },
                    "env_name": {
                        "type": "string",
                        "description": "Environment to focus on (optional)"
                    },
                    "lookback_days": {
                        "type": "integer",
                        "description": "Number of days to look back (default: 30)",
                        "default": 30
                    },
                    "max_hops": {
                        "type": "integer",
                        "description": "Maximum number of hops to trace (default: 4)",
                        "default": 4
                    }
                },
            }
        ),
        types.Tool(
            name="compliance-check",
            description="Check policy compliance against common frameworks (PCI-DSS, NIST, CIS). Identifies workloads in specific compliance scopes and verifies that segmentation policies meet framework requirements.",
            inputSchema={
                "type": "object",
                "properties": {
                    "framework": {
                        "type": "string",
                        "enum": ["pci-dss", "dora", "nist", "cis", "iso-27001", "swift-csp", "hipaa", "general"],
                        "description": "Compliance framework to check against (default: general). Read the corresponding illumio://compliance/* resource for detailed framework guidance.",
                        "default": "general"
                    },
                    "app_name": {
                        "type": "string",
                        "description": "Application to check (optional — if omitted, checks all apps)"
                    },
                    "env_name": {
                        "type": "string",
                        "description": "Environment to check (optional)"
                    },
                    "lookback_days": {
                        "type": "integer",
                        "description": "Number of days to look back for traffic analysis (default: 30)",
                        "default": 30
                    }
                },
            }
        ),
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    logger.debug(f"Handling tool call: {name} with arguments: {arguments}")
    
    if name == "get-workloads":
        # harmonize the logging
        logger.debug("=" * 80)  
        logger.debug("GET WORKLOADS CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        logger.debug("Initializing PCE connection")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            params = {"include": "labels", "max_results": arguments.get('max_results', 10000)}
            for param in ['name', 'hostname', 'ip_address', 'description', 'labels', 'enforcement_mode']:
                if arguments.get(param):
                    params[param] = arguments[param]
            if 'managed' in arguments:
                params['managed'] = arguments['managed']
            if 'online' in arguments:
                params['online'] = arguments['online']

            workloads = pce.workloads.get(params=params)
            logger.debug(f"Successfully retrieved {len(workloads)} workloads")
            return [types.TextContent(
                type="text",
                text=f"Workloads: {workloads}"
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]
    elif name == "check-pce-connection":
        logger.debug("Initializing PCE connection")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
            connection_status = pce.check_connection()
            return [types.TextContent(
                type="text",
                text=f"PCE connection successful: {connection_status}"
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]
    elif name == "create-label":
        logger.debug(f"Creating label with key: {arguments['key']} and value: {arguments['value']}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
            label = Label(key=arguments['key'], value=arguments['value'])
            label = pce.labels.create(label)
            logger.debug(f"Label created with status: {label}")
            return [types.TextContent(
                type="text",
                text=f"Label created with status: {label}"
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]
    elif name == "delete-label":
        logger.debug(f"Deleting label with key: {arguments['key']} and value: {arguments['value']}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
            label = pce.labels.get(params = { "key": arguments['key'], "value": arguments['value'] })
            if label:
                pce.labels.delete(label[0])
                return [types.TextContent(
                    type="text",
                    text=f"Label deleted with status: {label}"
                )]
            else:
                return [types.TextContent(
                    type="text",
                    text=f"Label not found"
                )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]
    elif name == "get-labels":
        logger.debug("Initializing PCE connection")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            params = {}
            if arguments.get('key'):
                params['key'] = arguments['key']
            if arguments.get('value'):
                params['value'] = arguments['value']
            if arguments.get('max_results'):
                params['max_results'] = arguments['max_results']
            if arguments.get('include_deleted'):
                params['include_deleted'] = arguments['include_deleted']
            if arguments.get('usage'):
                params['usage'] = arguments['usage']

            resp = pce.get('/labels', params=params)
            labels = resp.json()
            return [types.TextContent(
                type="text",
                text=f"Labels: {labels}"
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]
    elif name == "create-workload":
        logger.debug(f"Creating workload with name: {arguments['name']} and ip_addresses: {arguments['ip_addresses']}")
        logger.debug(f"Labels: {arguments['labels']}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            interfaces = []
            prefix = "eth"
            if_count = 0
            for ip in arguments['ip_addresses']:
                intf = Interface(name = f"{prefix}{if_count}", address = ip)
                interfaces.append(intf)
                if_count += 1

            workload_labels = []

            for label in arguments['labels']:
                logger.debug(f"Label: {label}")
                # check if label already exists
                label_resp = pce.labels.get(params = { "key": label['key'], "value": label['value'] })
                if label_resp:
                    logger.debug(f"Label already exists: {label_resp}")
                    workload_label = label_resp[0]  # Get the first matching label
                else:
                    logger.debug(f"Label does not exist, creating: {label}")
                    new_label = Label(key=label['key'], value=label['value'])
                    workload_label = pce.labels.create(new_label)

                workload_labels.append(workload_label)

            logger.debug(f"Labels: {workload_labels}")

            workload = Workload(
                name=arguments['name'], 
                interfaces=interfaces, 
                labels=workload_labels,
                hostname=arguments['name']  # Adding hostname which might be required
            )
            status = pce.workloads.create(workload)
            logger.debug(f"Workload creation status: {status}")
            return [types.TextContent(
                type="text",
                text=f"Workload created with status: {status}, workload: {workload}"
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]
    elif name == "update-workload":
        logger.debug(f"UPDATE WORKLOAD CALLED with arguments: {json.dumps(arguments, indent=2)}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            # Find the workload by href or name
            workload_obj = None
            if arguments.get("href"):
                workload_obj = pce.workloads.get_by_reference(arguments["href"])
            elif arguments.get("name"):
                workloads = pce.workloads.get(params={"name": arguments["name"]})
                if workloads:
                    workload_obj = workloads[0]

            if not workload_obj:
                return [types.TextContent(type="text", text=json.dumps({"error": "Workload not found"}))]

            # Build update payload via raw API for flexibility
            update_data = {}
            if "new_name" in arguments:
                update_data["name"] = arguments["new_name"]
            if "description" in arguments:
                update_data["description"] = arguments["description"]
            if "hostname" in arguments:
                update_data["hostname"] = arguments["hostname"]
            if "enforcement_mode" in arguments:
                update_data["enforcement_mode"] = arguments["enforcement_mode"]

            # Handle IP addresses -> interfaces
            if arguments.get("ip_addresses"):
                interfaces = []
                for i, ip in enumerate(arguments["ip_addresses"]):
                    interfaces.append({"name": f"eth{i}", "address": ip})
                update_data["interfaces"] = interfaces

            # Handle labels
            if "labels" in arguments:
                workload_labels = []
                for label_spec in arguments["labels"]:
                    label_resp = pce.labels.get(params={"key": label_spec["key"], "value": label_spec["value"]})
                    if label_resp:
                        workload_labels.append({"href": label_resp[0].href})
                    else:
                        new_label = Label(key=label_spec["key"], value=label_spec["value"])
                        created = pce.labels.create(new_label)
                        workload_labels.append({"href": created.href})
                update_data["labels"] = workload_labels

            if not update_data:
                return [types.TextContent(type="text", text=json.dumps({"error": "No update fields provided"}))]

            pce.put(workload_obj.href, json=update_data)

            return [types.TextContent(
                type="text",
                text=json.dumps({"message": f"Successfully updated workload {workload_obj.href}", "updated_fields": list(update_data.keys())}, indent=2)
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}))]
    elif name == "delete-workload":
        logger.debug(f"DELETE WORKLOAD CALLED with arguments: {json.dumps(arguments, indent=2)}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            workload_obj = None
            if arguments.get("href"):
                workload_obj = pce.workloads.get_by_reference(arguments["href"])
            elif arguments.get("name"):
                workloads = pce.workloads.get(params={"name": arguments["name"]})
                if workloads:
                    workload_obj = workloads[0]

            if workload_obj:
                pce.workloads.delete(workload_obj)
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"message": f"Workload deleted successfully: {workload_obj.href}"})
                )]
            else:
                return [types.TextContent(type="text", text=json.dumps({"error": "Workload not found"}))]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}))]
    elif name == "get-traffic-flows":
        logger.debug("=" * 80)
        logger.debug("GET TRAFFIC FLOWS CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        
        # assume a default start date of 1 day ago and end date of now
        if 'start_date' not in arguments:
            arguments['start_date'] = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
        if 'end_date' not in arguments:
            arguments['end_date'] = datetime.now().strftime('%Y-%m-%d')

        if not arguments or 'start_date' not in arguments or 'end_date' not in arguments:
            error_msg = "Missing required arguments: 'start_date' and 'end_date' are required"
            logger.error(error_msg)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg})
            )]

        logger.debug(f"Start Date: {arguments.get('start_date')}")
        logger.debug(f"End Date: {arguments.get('end_date')}")
        logger.debug(f"Include Sources: {arguments.get('include_sources', [])}")
        logger.debug(f"Exclude Sources: {arguments.get('exclude_sources', [])}")
        logger.debug(f"Include Destinations: {arguments.get('include_destinations', [])}")
        logger.debug(f"Exclude Destinations: {arguments.get('exclude_destinations', [])}")
        logger.debug(f"Include Services: {arguments.get('include_services', [])}")
        logger.debug(f"Exclude Services: {arguments.get('exclude_services', [])}")
        logger.debug(f"Policy Decisions: {arguments.get('policy_decisions', [])}")
        logger.debug(f"Exclude Workloads from IP List: {arguments.get('exclude_workloads_from_ip_list_query', True)}")
        logger.debug(f"Max Results: {arguments.get('max_results', 900)}")
        logger.debug(f"Query Name: {arguments.get('query_name')}")
        logger.debug("=" * 80)

        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            logger.debug(f"Due to a condition in MCP, max results is set to {MCP_BUG_MAX_RESULTS}")
            # TODO: fix this in the future...
            arguments['max_results'] = MCP_BUG_MAX_RESULTS

            traffic_query = TrafficQuery.build(
                start_date=arguments['start_date'],
                end_date=arguments['end_date'],
                include_sources=arguments.get('include_sources', [[]]),
                exclude_sources=arguments.get('exclude_sources', []),
                include_destinations=arguments.get('include_destinations', [[]]),
                exclude_destinations=arguments.get('exclude_destinations', []),
                include_services=arguments.get('include_services', []),
                exclude_services=arguments.get('exclude_services', []),
                policy_decisions=arguments.get('policy_decisions', []),
                exclude_workloads_from_ip_list_query=arguments.get('exclude_workloads_from_ip_list_query', True),
                max_results=arguments.get('max_results', 10000),
                query_name=arguments.get('query_name', 'mcp-traffic-query')
            )

            all_traffic = pce.get_traffic_flows_async(
                query_name=arguments.get('query_name', 'mcp-traffic-query'),
                traffic_query=traffic_query
            )
            
            df = to_dataframe(all_traffic)

            # Group by columns that exist, always including IP list names
            group_cols = ['src_ip', 'dst_ip', 'proto', 'port', 'policy_decision']
            for col in ['src_ip_lists', 'dst_ip_lists', 'src_hostname', 'dst_hostname']:
                if col in df.columns:
                    group_cols.append(col)
            group_cols = [c for c in group_cols if c in df.columns]
            df = df.groupby(group_cols).agg({'num_connections': 'sum'}).reset_index()

            # limit dataframe json output to less than 1048576
            MAX_ROWS = 1000
            if len(df) > MAX_ROWS:
                logger.warning(f"Truncating results from {len(df)} to {MAX_ROWS} entries")
                df = df.nlargest(MAX_ROWS, 'num_connections')

            response_size = len(df.to_json(orient="records"))

            if response_size > 1048576:
                logger.warning(f"Response size exceeds 1MB limit. Truncating to {MAX_ROWS} entries")
                step_down = 0.9
                while response_size > 1048576 or step_down == 0:
                    rows = int(MAX_ROWS * step_down)
                    step_down = step_down - 0.1
                    df = df.nlargest(rows, 'num_connections')
                    response_size = len(df.to_json(orient="records"))
                    logger.debug(f"Response size: {response_size} Step down: {step_down}")

            # trying this in case GC doesn't work
            df_json = df.to_json(orient="records")
            del df

            # return dataframe df in json format
            return [types.TextContent(
                type="text",
                text= df_json
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg})
            )]
    elif name == "get-traffic-flows-summary":
        logger.debug("=" * 80)
        logger.debug("GET TRAFFIC FLOWS SUMMARY CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug(f"Start Date: {arguments.get('start_date')}")
        logger.debug(f"End Date: {arguments.get('end_date')}")
        logger.debug(f"Include Sources: {arguments.get('include_sources', [])}")
        logger.debug(f"Exclude Sources: {arguments.get('exclude_sources', [])}")
        logger.debug(f"Include Destinations: {arguments.get('include_destinations', [])}")
        logger.debug(f"Exclude Destinations: {arguments.get('exclude_destinations', [])}")
        logger.debug(f"Include Services: {arguments.get('include_services', [])}")
        logger.debug(f"Exclude Services: {arguments.get('exclude_services', [])}")
        logger.debug(f"Policy Decisions: {arguments.get('policy_decisions', [])}")
        logger.debug(f"Exclude Workloads from IP List: {arguments.get('exclude_workloads_from_ip_list_query', True)}")
        logger.debug(f"Max Results: {arguments.get('max_results', 10000)}")
        logger.debug(f"Query Name: {arguments.get('query_name')}")
        logger.debug("=" * 80)

        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            logger.debug(f"Due to a condition in MCP, max results is set to {MCP_BUG_MAX_RESULTS}")
            # TODO: fix this in the future...
            if 'max_results' in arguments and arguments.get('max_results') > MCP_BUG_MAX_RESULTS:
                logger.debug(f"Setting max results to {MCP_BUG_MAX_RESULTS} from original value {arguments.get('max_results')}")
                arguments['max_results'] = MCP_BUG_MAX_RESULTS

            query = TrafficQuery.build(
                start_date=arguments['start_date'],
                end_date=arguments['end_date'],
                include_sources=arguments.get('include_sources', [[]]),
                exclude_sources=arguments.get('exclude_sources', []),
                include_destinations=arguments.get('include_destinations', [[]]),
                exclude_destinations=arguments.get('exclude_destinations', []),
                include_services=arguments.get('include_services', []),
                exclude_services=arguments.get('exclude_services', []),
                policy_decisions=arguments.get('policy_decisions', []),
                exclude_workloads_from_ip_list_query=arguments.get('exclude_workloads_from_ip_list_query', True),
                max_results=arguments.get('max_results', 10000),
                query_name=arguments.get('query_name', 'mcp-traffic-summary')
            )

            all_traffic = pce.get_traffic_flows_async(
                query_name=arguments.get('query_name', 'mcp-traffic-summary'),
                traffic_query=query
            )

            df = to_dataframe(all_traffic)
            summary = summarize_traffic(df)
            
            summary_lines = ""
            # Ensure the summary is a list of strings
            if isinstance(summary, list):
                # join list to be one string separated by newlines
                summary_lines = "\n".join(summary)
            else:
                summary_lines = str(summary)

            logger.debug(f"Summary data type: {type(summary_lines)}")
            logger.debug(f"Summary size: {len(summary_lines)}")

            return [types.TextContent(
                type="text",
                text=summary_lines
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg})
            )]
    elif name == "get-rulesets":
        logger.debug(f"GET RULESETS CALLED with arguments: {json.dumps(arguments, indent=2)}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            params = {}
            for param in ['name', 'description', 'labels']:
                if arguments.get(param):
                    params[param] = arguments[param]
            if 'enabled' in arguments and arguments['enabled'] is not None:
                params['enabled'] = arguments['enabled']
            if arguments.get('max_results'):
                params['max_results'] = arguments['max_results']

            rulesets = pce.rule_sets.get(params=params) if params else pce.rule_sets.get_all()
            
            # Convert rulesets to serializable format
            ruleset_data = []
            for ruleset in rulesets:
                rules = []
                for rule in ruleset.rules:
                    rule_dict = {
                        'rule_type': 'allow',
                        'enabled': rule.enabled,
                        'description': rule.description,
                        'resolve_labels_as': str(rule.resolve_labels_as) if rule.resolve_labels_as else None,
                        'consumers': [str(consumer) for consumer in rule.consumers] if rule.consumers else [],
                        'providers': [str(provider) for provider in rule.providers] if rule.providers else [],
                        'ingress_services': [str(service) for service in rule.ingress_services] if rule.ingress_services else []
                    }
                    rules.append(rule_dict)

                # Fetch deny rules via raw API (override flag distinguishes override deny rules)
                try:
                    resp = pce.get(f"{ruleset.href}/deny_rules")
                    deny_rules = resp.json()
                    if deny_rules:
                        for dr in deny_rules:
                            is_override = dr.get('override', False)
                            rule_dict = {
                                'rule_type': 'override_deny' if is_override else 'deny',
                                'href': dr.get('href'),
                                'enabled': dr.get('enabled'),
                                'description': dr.get('description'),
                                'consumers': [str(c) for c in dr.get('consumers', [])],
                                'providers': [str(p) for p in dr.get('providers', [])],
                                'ingress_services': [str(s) for s in dr.get('ingress_services', [])]
                            }
                            rules.append(rule_dict)
                except Exception as de:
                    logger.debug(f"Could not fetch deny_rules for {ruleset.href}: {de}")

                ruleset_dict = {
                    'href': ruleset.href,
                    'name': ruleset.name,
                    'enabled': ruleset.enabled,
                    'description': ruleset.description,
                    'scopes': [str(scope) for scope in ruleset.scopes] if ruleset.scopes else [],
                    'rules': rules
                }
                ruleset_data.append(ruleset_dict)

            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "rulesets": ruleset_data,
                    "total_count": len(ruleset_data)
                }, indent=2)
            )]

        except Exception as e:
            error_msg = f"Failed to get rulesets: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg})
            )]
    elif name == "get-iplists":
        logger.debug(f"GET IP LISTS CALLED with arguments: {json.dumps(arguments, indent=2)}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            params = {"max_results": arguments.get("max_results", 10000)}
            for param in ['name', 'description', 'fqdn', 'ip_address']:
                if arguments.get(param):
                    params[param] = arguments[param]

            ip_lists = pce.ip_lists.get(params=params)

            iplist_data = []
            for iplist in ip_lists:
                iplist_dict = {
                    'href': iplist.href,
                    'name': iplist.name,
                    'description': iplist.description,
                    'ip_ranges': [str(ip_range) for ip_range in iplist.ip_ranges] if iplist.ip_ranges else [],
                    'fqdns': iplist.fqdns if hasattr(iplist, 'fqdns') else [],
                    'created_at': str(iplist.created_at) if hasattr(iplist, 'created_at') else None,
                    'updated_at': str(iplist.updated_at) if hasattr(iplist, 'updated_at') else None,
                }
                iplist_data.append(iplist_dict)

            return [types.TextContent(
                type="text",
                text=json.dumps({"ip_lists": iplist_data, "total_count": len(iplist_data)}, indent=2)
            )]
        except Exception as e:
            error_msg = f"Failed to get IP lists: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}))]
    elif name == "get-events":
        logger.debug("=" * 80)
        logger.debug("GET EVENTS CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            params = {}
            for param in ['event_type', 'severity', 'status', 'max_results', 'created_by']:
                if arguments.get(param):
                    params[param] = arguments[param]
            if arguments.get('timestamp_gte'):
                params['timestamp[gte]'] = arguments['timestamp_gte']
            if arguments.get('timestamp_lte'):
                params['timestamp[lte]'] = arguments['timestamp_lte']

            events = pce.events.get(params=params)

            # Convert events to serializable format
            event_data = []
            for event in events:
                event_dict = {
                    'href': event.href,
                    'event_type': event.event_type,
                    'timestamp': str(event.timestamp) if hasattr(event, 'timestamp') else None,
                    'severity': event.severity if hasattr(event, 'severity') else None,
                    'status': event.status if hasattr(event, 'status') else None,
                    'created_by': str(event.created_by) if hasattr(event, 'created_by') else None,
                    'notification_type': event.notification_type if hasattr(event, 'notification_type') else None,
                    'info': event.info if hasattr(event, 'info') else None,
                    'pce_fqdn': event.pce_fqdn if hasattr(event, 'pce_fqdn') else None
                }
                event_data.append(event_dict)

            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "events": event_data,
                    "total_count": len(event_data)
                }, indent=2)
            )]

        except Exception as e:
            error_msg = f"Failed to get events: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg})
            )]
    elif name == "create-ruleset":
        logger.debug("=" * 80)
        logger.debug("CREATE RULESET CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            logger.debug("Initializing PCE connection...")
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
            
            # populate the label maps
            label_href_map = {}
            value_href_map = {}
            for l in pce.labels.get(params={'max_results': 10000}):
                label_href_map[l.href] = {"key": l.key, "value": l.value}
                value_href_map["{}={}".format(l.key, l.value)] = l.href

            # Check if ruleset already exists
            logger.debug(f"Checking if ruleset '{arguments['name']}' already exists...")
            existing_rulesets = pce.rule_sets.get(params={"name": arguments["name"]})
            if existing_rulesets:
                error_msg = f"Ruleset with name '{arguments['name']}' already exists"
                logger.error(error_msg)
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "error": error_msg,
                        "existing_ruleset": {
                            "href": existing_rulesets[0].href,
                            "name": existing_rulesets[0].name
                        }
                    }, indent=2)
                )]

            # Create the ruleset
            logger.debug(f"Instantiating ruleset object: {arguments['name']}")
            ruleset = RuleSet(
                name=arguments["name"],
                description=arguments.get("description", "")
            )

            # Handle scopes
            label_sets = []
            if arguments.get("scopes"):
                logger.debug(f"Processing scopes: {json.dumps(arguments['scopes'], indent=2)}")
                
                for scope in arguments["scopes"]:
                    label_set = LabelSet(labels=[])
                    for label in scope:
                        logger.debug(f"Processing label: {label}")
                        if isinstance(label, dict) and "href" in label:
                            # Handle direct href references
                            logger.debug(f"Found label with href: {label['href']}")
                            append_label = pce.labels.get_by_reference(label["href"])
                            logger.debug(f"Appending label: {append_label}")
                            label_set.labels.append(append_label)
                        elif isinstance(label, str):
                            # Handle string references (either href or label value)
                            if label in value_href_map:
                                logger.debug(f"Found label value: {value_href_map[label]}")
                                append_label = pce.labels.get_by_reference(value_href_map[label])
                            else:
                                logger.debug(f"Assuming direct href: {label}")
                                append_label = pce.labels.get_by_reference(label)
                            logger.debug(f"Appending label: {append_label}")
                            label_set.labels.append(append_label)
                        else:
                            logger.warning(f"Unexpected label format: {label}")
                            continue
                            
                    label_sets.append(label_set)
                    logger.debug(f"Label set: {label_set}")
            else:
                # If no scopes provided, create a default scope with all workloads
                logger.debug("No scopes provided, creating default scope with all workloads")
                label_sets = [LabelSet(labels=[])]

            logger.debug(f"Final ruleset scopes count: {len(label_sets)}")
            ruleset.scopes = label_sets

            # Create the ruleset in PCE
            logger.debug("Creating ruleset in PCE...")
            logger.debug(f"Ruleset object scopes: {[str(ls.labels) for ls in ruleset.scopes]}")
            ruleset = pce.rule_sets.create(ruleset)
            logger.debug(f"Ruleset created with href: {ruleset.href}")

            # Create rules if provided
            created_rules = []
            if arguments.get("rules"):
                logger.debug(f"Processing rules: {json.dumps(arguments['rules'], indent=2)}")
                
                for rule_def in arguments["rules"]:
                    logger.debug(f"Processing rule: {json.dumps(rule_def, indent=2)}")
                    
                    # Process providers
                    providers = []
                    for provider in rule_def["providers"]:
                        if provider == "ams":
                            providers.append(AMS)
                        elif provider.startswith("iplist:"):
                            # Extract IP list name and look it up
                            ip_list_name = provider.split(":", 1)[1]
                            logger.debug(f"Looking up IP list: {ip_list_name}")
                            ip_lists = pce.ip_lists.get(params={"name": ip_list_name})
                            if ip_lists:
                                providers.append(ip_lists[0])
                            else:
                                logger.error(f"IP list not found: {ip_list_name}")
                                return [types.TextContent(
                                    type="text",
                                    text=json.dumps({"error": f"IP list not found: {ip_list_name}"})
                                )]
                        elif provider in value_href_map:
                            providers.append(pce.labels.get_by_reference(value_href_map[provider]))
                        else:
                            providers.append(pce.labels.get_by_reference(provider))
                    
                    # Process consumers
                    consumers = []
                    for consumer in rule_def["consumers"]:
                        if consumer == "ams":
                            consumers.append(AMS)
                        elif consumer.startswith("iplist:"):
                            # Extract IP list name and look it up
                            ip_list_name = consumer.split(":", 1)[1]
                            logger.debug(f"Looking up IP list: {ip_list_name}")
                            ip_lists = pce.ip_lists.get(params={"name": ip_list_name})
                            if ip_lists:
                                consumers.append(ip_lists[0])
                            else:
                                logger.error(f"IP list not found: {ip_list_name}")
                                return [types.TextContent(
                                    type="text",
                                    text=json.dumps({"error": f"IP list not found: {ip_list_name}"})
                                )]
                        elif consumer in value_href_map:
                            consumers.append(pce.labels.get_by_reference(value_href_map[consumer]))
                        else:
                            consumers.append(pce.labels.get_by_reference(consumer))
                    
                    # Create ingress services
                    ingress_services = []
                    for svc in rule_def["ingress_services"]:
                        service_port = ServicePort(
                            port=svc["port"],
                            proto=svc["proto"]
                        )
                        ingress_services.append(service_port)
                    
                    # Determine rule type
                    rule_type = rule_def.get("rule_type", "allow")

                    if rule_type in ("deny", "override_deny"):
                        # Deny/override deny rules use raw API since SDK doesn't support rule_type
                        proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
                        raw_providers = []
                        for p in providers:
                            if p == AMS:
                                raw_providers.append({"actors": "ams"})
                            elif hasattr(p, 'href') and hasattr(p, 'key'):
                                raw_providers.append({"label": {"href": p.href}})
                            elif hasattr(p, 'href'):
                                raw_providers.append({"ip_list": {"href": p.href}})
                        raw_consumers = []
                        for c in consumers:
                            if c == AMS:
                                raw_consumers.append({"actors": "ams"})
                            elif hasattr(c, 'href') and hasattr(c, 'key'):
                                raw_consumers.append({"label": {"href": c.href}})
                            elif hasattr(c, 'href'):
                                raw_consumers.append({"ip_list": {"href": c.href}})
                        raw_services = []
                        for svc in ingress_services:
                            proto_val = svc.proto
                            if isinstance(proto_val, str):
                                proto_val = proto_map.get(proto_val.lower(), proto_val)
                            raw_services.append({"port": svc.port, "proto": proto_val})

                        rule_payload = {
                            "enabled": True,
                            "providers": raw_providers,
                            "consumers": raw_consumers,
                            "ingress_services": raw_services,
                            "unscoped_consumers": rule_def.get("unscoped_consumers", False),
                            "override": rule_type == "override_deny"
                        }

                        endpoint = f"{ruleset.href}/deny_rules"

                        logger.debug(f"Creating {rule_type} rule at: {endpoint}")
                        resp = pce.post(endpoint, json=rule_payload)
                        result = resp.json()
                        created_rules.append({
                            "href": result.get("href", ""),
                            "rule_type": rule_type,
                            "providers": [str(p) for p in providers],
                            "consumers": [str(c) for c in consumers],
                            "services": [f"{s.port}/{s.proto}" for s in ingress_services],
                            "unscoped_consumers": rule_def.get("unscoped_consumers", False)
                        })
                    else:
                        # Standard allow rule using SDK
                        rule = Rule.build(
                            providers=providers,
                            consumers=consumers,
                            ingress_services=ingress_services,
                            unscoped_consumers=rule_def.get("unscoped_consumers", False)
                        )

                        created_rule = pce.rules.create(rule, parent=ruleset)
                        created_rules.append({
                            "href": created_rule.href,
                            "rule_type": "allow",
                            "providers": [str(p) for p in providers],
                            "consumers": [str(c) for c in consumers],
                            "services": [f"{s.port}/{s.proto}" for s in ingress_services],
                            "unscoped_consumers": rule_def.get("unscoped_consumers", False)
                        })
            
            # Update the response to include rules
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "ruleset": {
                        "href": ruleset.href,
                        "name": ruleset.name,
                        "description": ruleset.description,
                        "rules": created_rules
                    }
                }, indent=2)
            )]

        except Exception as e:
            error_msg = f"Failed to create ruleset: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg})
            )]
    elif name == "get-services":
        logger.debug("=" * 80)
        logger.debug("GET SERVICES CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            logger.debug("Initializing PCE connection...")
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            params = {}
            for param in ['name', 'description', 'port', 'proto', 'process_name', 'max_results']:
                if arguments.get(param):
                    params[param] = arguments[param]
            
            logger.debug(f"Querying services with params: {json.dumps(params, indent=2)}")
            services = pce.services.get(params=params)
            logger.debug(f"Found {len(services)} services")
            
            # Convert services to serializable format
            service_data = []
            for service in services:
                logger.debug(f"Processing service: {service.name} ({service.href})")
                service_dict = {
                    'href': service.href,
                    'name': service.name,
                    'description': service.description if hasattr(service, 'description') else None,
                    'process_name': service.process_name if hasattr(service, 'process_name') else None,
                    'service_ports': []
                }
                
                # Add service ports - check both possible attribute names
                ports = []
                if hasattr(service, 'service_ports'):
                    # logger.debug(f"Found service_ports attribute for {service.name}")
                    ports = service.service_ports or []  # Handle None case
                elif hasattr(service, 'ports'):
                    # logger.debug(f"Found ports attribute for {service.name}")
                    ports = service.ports or []  # Handle None case
                
                logger.debug(f"Processing {len(ports)} ports for service {service.name}")
                for port in ports:
                    try:
                        port_dict = {
                            'port': port.port,
                            'proto': port.proto
                        }
                        # Only add to_port if it exists and is different from port
                        if hasattr(port, 'to_port') and port.to_port is not None:
                            port_dict['to_port'] = port.to_port
                        service_dict['service_ports'].append(port_dict)
                        logger.debug(f"Added port {port.port}/{port.proto} to service {service.name}")
                    except AttributeError as e:
                        logger.warning(f"Error processing port {port} for service {service.name}: {e}")
                        continue

                # Add windows services if present
                if hasattr(service, 'windows_services'):
                    logger.debug(f"Found windows_services for {service.name}")
                    service_dict['windows_services'] = service.windows_services

                service_data.append(service_dict)
                logger.debug(f"Completed processing service: {service.name}")

            logger.debug(f"Service data: {json.dumps(service_data, indent=2)}")
            logger.debug(f"Successfully processed {len(service_data)} services")
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "services": service_data,
                    "total_count": len(service_data)
                }, indent=2)
            )]

        except Exception as e:
            error_msg = f"Failed to get services: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg})
            )]
    elif name == "update-label":
        logger.debug("Initializing PCE connection")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
            
            href = arguments.get("href")
            key = arguments.get("key")
            value = arguments.get("value")
            new_value = arguments.get("new_value")
            
            # First, find the label
            label = None
            if href:
                logger.debug(f"Looking up label by href: {href}")
                try:
                    label = pce.labels.get_by_reference(href)
                    logger.debug(f"Found label by href: {label}")
                except Exception as e:
                    logger.error(f"Failed to find label by href {href}: {str(e)}")
                    return [types.TextContent(
                        type="text",
                        text=f"Error: Label with href {href} not found"
                    )]
            else:
                logger.debug(f"Looking up label by key={key}, value={value}")
                labels = pce.labels.get(params={"key": key, "value": value})
                if labels and len(labels) > 0:
                    label = labels[0]  # Get the first matching label
                    logger.debug(f"Found label by key-value: {label}")
                else:
                    logger.error(f"No label found with key={key}, value={value}")
                    return [types.TextContent(
                        type="text",
                        text=f"Error: No label found with key={key}, value={value}"
                    )]
            
            if label:
                logger.debug(f"Updating label {label.href} with new_value={new_value}")
                # Prepare the update payload - only include the new value
                update_data = {
                    "value": new_value
                }
                
                # Update the label
                updated_label = pce.labels.update(label.href, update_data)
                logger.debug(f"Label updated successfully: {updated_label}")
                
                return [types.TextContent(
                    type="text",
                    text=f"Successfully updated label: {updated_label}"
                )]
            else:
                error_msg = "Failed to find label to update"
                logger.error(error_msg)
                return [types.TextContent(
                    type="text",
                    text=f"Error: {error_msg}"
                )]
                
        except Exception as e:
            error_msg = f"Failed to update label: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]
    elif name == "create-iplist":
        logger.debug("=" * 80)
        logger.debug("CREATE IP LIST CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            logger.debug("Initializing PCE connection...")
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            # Check if IP List already exists
            logger.debug(f"Checking if IP List '{arguments['name']}' already exists...")
            existing_iplists = pce.ip_lists.get(params={"name": arguments["name"]})
            if existing_iplists:
                error_msg = f"IP List with name '{arguments['name']}' already exists"
                logger.error(error_msg)
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "error": error_msg,
                        "existing_iplist": {
                            "href": existing_iplists[0].href,
                            "name": existing_iplists[0].name
                        }
                    }, indent=2)
                )]

            # Create IP ranges
            ip_ranges = []
            for range_def in arguments["ip_ranges"]:
                ip_range = {
                    "from_ip": range_def["from_ip"],
                    "exclusion": range_def.get("exclusion", False)
                }
                
                # Add optional fields if present
                if "to_ip" in range_def:
                    ip_range["to_ip"] = range_def["to_ip"]
                if "description" in range_def:
                    ip_range["description"] = range_def["description"]
                
                ip_ranges.append(ip_range)

            # Create the IP List object
            iplist_data = {
                "name": arguments["name"],
                "ip_ranges": ip_ranges
            }

            # Add optional fields if present
            if "description" in arguments:
                iplist_data["description"] = arguments["description"]
            if "fqdn" in arguments:
                iplist_data["fqdn"] = arguments["fqdn"]

            logger.debug(f"Creating IP List with data: {json.dumps(iplist_data, indent=2)}")
            iplist = pce.ip_lists.create(iplist_data)
            
            # Format response
            response_data = {
                "href": iplist.href,
                "name": iplist.name,
                "description": getattr(iplist, "description", None),
                "ip_ranges": [
                    {
                        "from_ip": r.from_ip,
                        "to_ip": getattr(r, "to_ip", None),
                        "description": getattr(r, "description", None),
                        "exclusion": getattr(r, "exclusion", False)
                    } for r in iplist.ip_ranges
                ],
                "fqdn": getattr(iplist, "fqdn", None)
            }

            return [types.TextContent(
                type="text",
                text=json.dumps(response_data, indent=2)
            )]

        except Exception as e:
            error_msg = f"Failed to create IP List: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg}, indent=2)
            )]
    elif name == "update-iplist":
        logger.debug("=" * 80)
        logger.debug("UPDATE IP LIST CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            logger.debug("Initializing PCE connection...")
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            # Find the IP List
            iplist = None
            if "href" in arguments:
                logger.debug(f"Looking up IP List by href: {arguments['href']}")
                try:
                    iplist = pce.ip_lists.get_by_reference(arguments['href'])
                except Exception as e:
                    logger.error(f"Failed to find IP List by href: {str(e)}")
                    return [types.TextContent(
                        type="text",
                        text=json.dumps({"error": f"IP List not found: {str(e)}"}, indent=2)
                    )]
            else:
                logger.debug(f"Looking up IP List by name: {arguments['name']}")
                iplists = pce.ip_lists.get(params={"name": arguments["name"]})
                if iplists:
                    iplist = iplists[0]
                else:
                    return [types.TextContent(
                        type="text",
                        text=json.dumps({"error": f"IP List with name '{arguments['name']}' not found"}, indent=2)
                    )]

            logger.debug(f"Found IP List: {iplist.href}, {iplist.name}")

            # Prepare update data
            update_data = {}
            if "description" in arguments:
                update_data["description"] = arguments["description"]
            if "fqdn" in arguments:
                update_data["fqdn"] = arguments["fqdn"]
            if "ip_ranges" in arguments:
                ip_ranges = []
                for range_def in arguments["ip_ranges"]:
                    ip_range = {
                        "from_ip": range_def["from_ip"],
                        "exclusion": range_def.get("exclusion", False)
                    }
                    if "to_ip" in range_def:
                        ip_range["to_ip"] = range_def["to_ip"]
                    if "description" in range_def:
                        ip_range["description"] = range_def["description"]
                    ip_ranges.append(ip_range)
                update_data["ip_ranges"] = ip_ranges

            logger.debug(f"Updating IP List with data: {json.dumps(update_data, indent=2)}")
            
            # Update the IP List
            pce.ip_lists.update(iplist.href, update_data)
            
            # Fetch the updated IP List to get the current state
            updated_iplist = pce.ip_lists.get_by_reference(iplist.href)
            
            # Format response
            response_data = {
                "href": updated_iplist.href,
                "name": updated_iplist.name,
                "description": getattr(updated_iplist, "description", None),
                "ip_ranges": []
            }
            
            # Safely add IP ranges if they exist
            if hasattr(updated_iplist, 'ip_ranges') and updated_iplist.ip_ranges:
                for r in updated_iplist.ip_ranges:
                    range_data = {"from_ip": r.from_ip}
                    if hasattr(r, "to_ip"):
                        range_data["to_ip"] = r.to_ip
                    if hasattr(r, "description"):
                        range_data["description"] = r.description
                    if hasattr(r, "exclusion"):
                        range_data["exclusion"] = r.exclusion
                    response_data["ip_ranges"].append(range_data)
            
            # Add FQDN if it exists
            if hasattr(updated_iplist, "fqdn"):
                response_data["fqdn"] = updated_iplist.fqdn

            return [types.TextContent(
                type="text",
                text=json.dumps(response_data, indent=2)
            )]

        except Exception as e:
            error_msg = f"Failed to update IP List: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg}, indent=2)
            )]
    elif name == "delete-iplist":
        logger.debug("=" * 80)
        logger.debug("DELETE IP LIST CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            logger.debug("Initializing PCE connection...")
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            # Find the IP List
            iplist = None
            if "href" in arguments:
                logger.debug(f"Looking up IP List by href: {arguments['href']}")
                try:
                    iplist = pce.ip_lists.get_by_reference(arguments['href'])
                except Exception as e:
                    logger.error(f"Failed to find IP List by href: {str(e)}")
                    return [types.TextContent(
                        type="text",
                        text=json.dumps({"error": f"IP List not found: {str(e)}"}, indent=2)
                    )]
            else:
                logger.debug(f"Looking up IP List by name: {arguments['name']}")
                iplists = pce.ip_lists.get(params={"name": arguments["name"]})
                if iplists:
                    iplist = iplists[0]
                else:
                    return [types.TextContent(
                        type="text",
                        text=json.dumps({"error": f"IP List with name '{arguments['name']}' not found"}, indent=2)
                    )]

            # Delete the IP List
            logger.debug(f"Deleting IP List: {iplist.href}")
            pce.ip_lists.delete(iplist.href)

            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "message": f"Successfully deleted IP List: {iplist.name}",
                    "href": iplist.href
                }, indent=2)
            )]

        except Exception as e:
            error_msg = f"Failed to delete IP List: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg}, indent=2)
            )]
    elif name == "update-ruleset":
        logger.debug("=" * 80)
        logger.debug("UPDATE RULESET CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            logger.debug("Initializing PCE connection...")
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            # Find the ruleset
            ruleset = None
            if "href" in arguments:
                logger.debug(f"Looking up ruleset by href: {arguments['href']}")
                try:
                    ruleset = pce.rule_sets.get_by_reference(arguments['href'])
                except Exception as e:
                    logger.error(f"Failed to find ruleset by href: {str(e)}")
                    return [types.TextContent(
                        type="text",
                        text=json.dumps({"error": f"Ruleset not found: {str(e)}"}, indent=2)
                    )]
            else:
                logger.debug(f"Looking up ruleset by name: {arguments['name']}")
                rulesets = pce.rule_sets.get(params={"name": arguments["name"]})
                if rulesets:
                    ruleset = rulesets[0]
                else:
                    return [types.TextContent(
                        type="text",
                        text=json.dumps({"error": f"Ruleset with name '{arguments['name']}' not found"}, indent=2)
                    )]

            # Prepare update data
            update_data = {}
            if "description" in arguments:
                update_data["description"] = arguments["description"]
            if "enabled" in arguments:
                update_data["enabled"] = arguments["enabled"]

            # Handle scopes if provided
            if "scopes" in arguments:
                logger.debug(f"Processing scopes: {json.dumps(arguments['scopes'], indent=2)}")
                label_sets = []
                
                for scope in arguments["scopes"]:
                    label_set = LabelSet(labels=[])
                    for label in scope:
                        logger.debug(f"Processing label: {label}")
                        if isinstance(label, dict) and "href" in label:
                            # Handle direct href references
                            logger.debug(f"Found label with href: {label['href']}")
                            append_label = pce.labels.get_by_reference(label["href"])
                            logger.debug(f"Appending label: {append_label}")
                            label_set.labels.append(append_label)
                        elif isinstance(label, str):
                            # Handle string references (either href or label value)
                            if "=" in label:  # key=value format
                                key, value = label.split("=", 1)
                                labels = pce.labels.get(params={"key": key, "value": value})
                                if labels:
                                    append_label = labels[0]
                                    logger.debug(f"Appending label: {append_label}")
                                    label_set.labels.append(append_label)
                            else:  # direct href
                                append_label = pce.labels.get_by_reference(label)
                                logger.debug(f"Appending label: {append_label}")
                                label_set.labels.append(append_label)
                    
                    label_sets.append(label_set)
                    logger.debug(f"Label set: {label_set}")
                
                update_data["scopes"] = label_sets

            # Update the ruleset
            logger.debug(f"Updating ruleset with data: {update_data}")
            pce.rule_sets.update(ruleset.href, update_data)

            # Re-fetch the ruleset to get updated state
            updated_ruleset = pce.rule_sets.get_by_reference(ruleset.href)

            # Format response
            response_data = {
                "href": updated_ruleset.href,
                "name": updated_ruleset.name,
                "description": getattr(updated_ruleset, "description", None),
                "enabled": getattr(updated_ruleset, "enabled", None),
                "scopes": []
            }

            # Add scopes if they exist
            if hasattr(updated_ruleset, "scopes"):
                for scope in updated_ruleset.scopes:
                    scope_labels = []
                    for label in scope.labels:
                        scope_labels.append({
                            "href": label.href,
                            "key": label.key,
                            "value": label.value
                        })
                    response_data["scopes"].append(scope_labels)

            return [types.TextContent(
                type="text",
                text=json.dumps(response_data, indent=2)
            )]

        except Exception as e:
            error_msg = f"Failed to update ruleset: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg}, indent=2)
            )]

    elif name == "delete-ruleset":
        logger.debug("=" * 80)
        logger.debug("DELETE RULESET CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            logger.debug("Initializing PCE connection...")
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            # Find the ruleset
            ruleset = None
            if "href" in arguments:
                logger.debug(f"Looking up ruleset by href: {arguments['href']}")
                try:
                    ruleset = pce.rule_sets.get_by_reference(arguments['href'])
                except Exception as e:
                    logger.error(f"Failed to find ruleset by href: {str(e)}")
                    return [types.TextContent(
                        type="text",
                        text=json.dumps({"error": f"Ruleset not found: {str(e)}"}, indent=2)
                    )]
            else:
                logger.debug(f"Looking up ruleset by name: {arguments['name']}")
                rulesets = pce.rule_sets.get(params={"name": arguments["name"]})
                if rulesets:
                    ruleset = rulesets[0]
                else:
                    return [types.TextContent(
                        type="text",
                        text=json.dumps({"error": f"Ruleset with name '{arguments['name']}' not found"}, indent=2)
                    )]

            # Delete the ruleset
            logger.debug(f"Deleting ruleset: {ruleset.href}")
            pce.rule_sets.delete(ruleset.href)

            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "message": f"Successfully deleted ruleset: {ruleset.name}",
                    "href": ruleset.href
                }, indent=2)
            )]

        except Exception as e:
            error_msg = f"Failed to delete ruleset: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg}, indent=2)
            )]

    elif name == "create-deny-rule":
        logger.debug("=" * 80)
        logger.debug("CREATE DENY RULE CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            # Build label maps
            label_href_map = {}
            value_href_map = {}
            for l in pce.labels.get(params={'max_results': 10000}):
                label_href_map[l.href] = {"key": l.key, "value": l.value}
                value_href_map["{}={}".format(l.key, l.value)] = l.href

            # Find the ruleset
            ruleset_href = None
            if arguments.get("ruleset_href"):
                ruleset_href = arguments["ruleset_href"]
                # Ensure it's a draft href
                if '/active/' in ruleset_href:
                    ruleset_href = ruleset_href.replace('/active/', '/draft/')
            elif arguments.get("ruleset_name"):
                rulesets = pce.rule_sets.get(params={"name": arguments["ruleset_name"]})
                if not rulesets:
                    return [types.TextContent(
                        type="text",
                        text=json.dumps({"error": f"Ruleset '{arguments['ruleset_name']}' not found"}, indent=2)
                    )]
                ruleset_href = rulesets[0].href
                if '/active/' in ruleset_href:
                    ruleset_href = ruleset_href.replace('/active/', '/draft/')
            else:
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": "Must provide either 'ruleset_href' or 'ruleset_name'"}, indent=2)
                )]

            is_override = arguments.get("override_deny", False)
            rule_type = "override_deny" if is_override else "deny"

            # Guardrail: warn about override deny usage
            override_warning = None
            if is_override:
                override_warning = (
                    "IMPORTANT: You are creating an OVERRIDE DENY rule. This is the highest priority deny "
                    "in Illumio — it blocks traffic even when allow rules exist, overriding everything. "
                    "Override deny means 'this traffic must not happen under any circumstances.' "
                    "Use cases: emergency isolation of compromised systems, hard compliance blocks "
                    "(e.g., PCI zones that must never reach the internet), or any scenario where "
                    "no allow rule should ever override the block. "
                    "Do NOT use override deny for normal segmentation or ringfencing — use regular deny rules instead. "
                    "Rule processing order: Essential > Override Deny > Allow > Deny > Default."
                )
                logger.warning(f"Override deny rule being created: {override_warning}")

            # Build providers
            providers = []
            for provider in arguments["providers"]:
                if provider == "ams":
                    providers.append({"actors": "ams"})
                elif provider.startswith("iplist:"):
                    ip_list_name = provider.split(":", 1)[1]
                    ip_lists = pce.ip_lists.get(params={"name": ip_list_name})
                    if ip_lists:
                        providers.append({"ip_list": {"href": ip_lists[0].href}})
                    else:
                        return [types.TextContent(
                            type="text",
                            text=json.dumps({"error": f"IP list not found: {ip_list_name}"})
                        )]
                elif provider in value_href_map:
                    providers.append({"label": {"href": value_href_map[provider]}})
                else:
                    providers.append({"label": {"href": provider}})

            # Build consumers
            consumers = []
            for consumer in arguments["consumers"]:
                if consumer == "ams":
                    consumers.append({"actors": "ams"})
                elif consumer.startswith("iplist:"):
                    ip_list_name = consumer.split(":", 1)[1]
                    ip_lists = pce.ip_lists.get(params={"name": ip_list_name})
                    if ip_lists:
                        consumers.append({"ip_list": {"href": ip_lists[0].href}})
                    else:
                        return [types.TextContent(
                            type="text",
                            text=json.dumps({"error": f"IP list not found: {ip_list_name}"})
                        )]
                elif consumer in value_href_map:
                    consumers.append({"label": {"href": value_href_map[consumer]}})
                else:
                    consumers.append({"label": {"href": consumer}})

            # Build ingress services
            proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
            ingress_services = []
            for svc in arguments["ingress_services"]:
                proto_val = svc["proto"]
                if isinstance(proto_val, str):
                    proto_val = proto_map.get(proto_val.lower(), proto_val)
                ingress_services.append({"port": svc["port"], "proto": proto_val})

            # Build the rule payload
            rule_payload = {
                "enabled": True,
                "providers": providers,
                "consumers": consumers,
                "ingress_services": ingress_services,
                "unscoped_consumers": arguments.get("unscoped_consumers", False),
                "override": rule_type == "override_deny"
            }

            endpoint = f"{ruleset_href}/deny_rules"

            logger.debug(f"Creating {rule_type} rule at endpoint: {endpoint}")
            logger.debug(f"Rule payload: {json.dumps(rule_payload, indent=2)}")

            resp = pce.post(endpoint, json=rule_payload)
            result = resp.json()

            response = {
                    "message": f"Successfully created {rule_type} rule",
                    "rule": result
                }
            if override_warning:
                response["override_deny_warning"] = override_warning

            return [types.TextContent(
                type="text",
                text=json.dumps(response, indent=2)
            )]

        except Exception as e:
            error_msg = f"Failed to create deny rule: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg}, indent=2)
            )]

    elif name == "update-deny-rule":
        logger.debug(f"UPDATE DENY RULE CALLED with arguments: {json.dumps(arguments, indent=2)}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            href = arguments["href"]
            if '/active/' in href:
                href = href.replace('/active/', '/draft/')

            update_data = {}
            if "enabled" in arguments:
                update_data["enabled"] = arguments["enabled"]

            # Build label maps if providers/consumers use key=value
            if arguments.get("providers") or arguments.get("consumers"):
                label_href_map = {}
                value_href_map = {}
                for l in pce.labels.get(params={'max_results': 10000}):
                    label_href_map[l.href] = {"key": l.key, "value": l.value}
                    value_href_map[f"{l.key}={l.value}"] = l.href

            if arguments.get("providers"):
                raw_providers = []
                for p in arguments["providers"]:
                    if p == "ams":
                        raw_providers.append({"actors": "ams"})
                    elif p.startswith("iplist:"):
                        ip_lists = pce.ip_lists.get(params={"name": p.split(":", 1)[1]})
                        if ip_lists:
                            raw_providers.append({"ip_list": {"href": ip_lists[0].href}})
                    elif p in value_href_map:
                        raw_providers.append({"label": {"href": value_href_map[p]}})
                    else:
                        raw_providers.append({"label": {"href": p}})
                update_data["providers"] = raw_providers

            if arguments.get("consumers"):
                raw_consumers = []
                for c in arguments["consumers"]:
                    if c == "ams":
                        raw_consumers.append({"actors": "ams"})
                    elif c.startswith("iplist:"):
                        ip_lists = pce.ip_lists.get(params={"name": c.split(":", 1)[1]})
                        if ip_lists:
                            raw_consumers.append({"ip_list": {"href": ip_lists[0].href}})
                    elif c in value_href_map:
                        raw_consumers.append({"label": {"href": value_href_map[c]}})
                    else:
                        raw_consumers.append({"label": {"href": c}})
                update_data["consumers"] = raw_consumers

            if arguments.get("ingress_services"):
                proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
                raw_services = []
                for svc in arguments["ingress_services"]:
                    proto_val = svc["proto"]
                    if isinstance(proto_val, str):
                        proto_val = proto_map.get(proto_val.lower(), proto_val)
                    raw_services.append({"port": svc["port"], "proto": proto_val})
                update_data["ingress_services"] = raw_services

            if not update_data:
                return [types.TextContent(type="text", text=json.dumps({"error": "No update fields provided"}))]

            pce.put(href, json=update_data)

            return [types.TextContent(
                type="text",
                text=json.dumps({"message": f"Successfully updated deny rule {href}", "updated_fields": list(update_data.keys())}, indent=2)
            )]
        except Exception as e:
            error_msg = f"Failed to update deny rule: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

    elif name == "delete-deny-rule":
        logger.debug(f"DELETE DENY RULE CALLED with arguments: {json.dumps(arguments, indent=2)}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            href = arguments["href"]
            if '/active/' in href:
                href = href.replace('/active/', '/draft/')

            pce.delete(href)

            return [types.TextContent(
                type="text",
                text=json.dumps({"message": f"Successfully deleted deny rule {href}"}, indent=2)
            )]
        except Exception as e:
            error_msg = f"Failed to delete deny rule: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

    elif name == "create-ringfence":
        logger.debug("=" * 80)
        logger.debug("CREATE RINGFENCE CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            app_name = arguments["app_name"]
            env_name = arguments["env_name"]
            lookback_days = arguments.get("lookback_days", 30)
            dry_run = arguments.get("dry_run", False)
            selective = arguments.get("selective", False)
            deny_consumer = arguments.get("deny_consumer", "any")
            skip_allowed = arguments.get("skip_allowed", False)
            rs_name = arguments.get("ruleset_name", f"RF-{app_name}-{env_name}")

            # Step 1: Find app and env labels
            app_labels = pce.labels.get(params={"key": "app", "value": app_name})
            if not app_labels:
                return [types.TextContent(type="text", text=json.dumps({"error": f"App label '{app_name}' not found"}))]
            app_label = app_labels[0]

            env_labels = pce.labels.get(params={"key": "env", "value": env_name})
            if not env_labels:
                return [types.TextContent(type="text", text=json.dumps({"error": f"Env label '{env_name}' not found"}))]
            env_label = env_labels[0]

            logger.debug(f"Found labels: app={app_label.href}, env={env_label.href}")

            # Build label maps for resolving traffic flow labels
            label_href_map = {}
            for l in pce.labels.get(params={'max_results': 10000}):
                label_href_map[l.href] = {"key": l.key, "value": l.value}

            # Step 2: Find "All Services" service object and "Any (0.0.0.0/0)" IP list
            all_services = pce.services.get(params={"name": "All Services"})
            all_services_href = None
            if all_services:
                all_services_href = all_services[0].href
                logger.debug(f"Found All Services: {all_services_href}")
            else:
                logger.warning("'All Services' service object not found, will use port -1 fallback")

            any_iplist_href = None
            if deny_consumer in ("any", "ams_and_any"):
                any_iplists = pce.ip_lists.get(params={"name": "Any (0.0.0.0/0 and ::/0)"})
                if any_iplists:
                    any_iplist_href = any_iplists[0].href
                    logger.debug(f"Found Any IP list: {any_iplist_href}")
                else:
                    # Try alternate name
                    any_iplists = pce.ip_lists.get(params={"name": "Any (0.0.0.0/0)"})
                    if any_iplists:
                        any_iplist_href = any_iplists[0].href
                        logger.debug(f"Found Any IP list (alt name): {any_iplist_href}")
                    else:
                        logger.warning("'Any' IP list not found, falling back to deny_consumer='ams'")
                        deny_consumer = "ams"

            # Step 3: Query traffic flows for this app+env (as destination = inbound)
            start_date = (datetime.now() - timedelta(days=lookback_days)).strftime('%Y-%m-%d')
            end_date = datetime.now().strftime('%Y-%m-%d')

            # Build TrafficQueryFilter objects for the app+env labels
            app_filter = TrafficQueryFilter(label=Reference(href=app_label.href))
            env_filter = TrafficQueryFilter(label=Reference(href=env_label.href))

            traffic_query = TrafficQuery.build(
                start_date=start_date,
                end_date=end_date,
                include_sources=[[]],
                exclude_sources=[],
                include_destinations=[[app_filter, env_filter]],
                exclude_destinations=[],
                include_services=[],
                exclude_services=[],
                policy_decisions=[],
                exclude_workloads_from_ip_list_query=True,
                max_results=MCP_BUG_MAX_RESULTS,
                query_name='ringfence-inbound'
            )

            logger.debug("Querying inbound traffic flows...")
            inbound_flows = pce.get_traffic_flows_async(
                query_name='ringfence-inbound',
                traffic_query=traffic_query
            )

            # Step 4: Also query outbound traffic (this app as source)
            traffic_query_out = TrafficQuery.build(
                start_date=start_date,
                end_date=end_date,
                include_sources=[[app_filter, env_filter]],
                exclude_sources=[],
                include_destinations=[[]],
                exclude_destinations=[],
                include_services=[],
                exclude_services=[],
                policy_decisions=[],
                exclude_workloads_from_ip_list_query=True,
                max_results=MCP_BUG_MAX_RESULTS,
                query_name='ringfence-outbound'
            )

            logger.debug("Querying outbound traffic flows...")
            outbound_flows = pce.get_traffic_flows_async(
                query_name='ringfence-outbound',
                traffic_query=traffic_query_out
            )

            # Step 5: Convert flows to dataframes and group by app+env
            inbound_df = to_dataframe(inbound_flows)
            outbound_df = to_dataframe(outbound_flows)

            remote_apps_inbound = {}  # key: (app_value, env_value) -> list of {port, proto, connections}
            remote_apps_outbound = {}
            remote_apps_policy = {}  # key: (app_value, env_value) -> set of policy_decisions

            if not inbound_df.empty:
                # Group inbound by source app+env to find unique remote apps connecting in
                src_group_cols = []
                if 'src_app' in inbound_df.columns:
                    src_group_cols.append('src_app')
                if 'src_env' in inbound_df.columns:
                    src_group_cols.append('src_env')
                if src_group_cols and 'port' in inbound_df.columns and 'proto' in inbound_df.columns:
                    group_cols = src_group_cols + ['port', 'proto']
                    if 'policy_decision' in inbound_df.columns:
                        group_cols.append('policy_decision')
                    group_cols = [c for c in group_cols if c in inbound_df.columns]
                    inbound_grouped = inbound_df.groupby(group_cols)['num_connections'].sum().reset_index()
                    for _, row in inbound_grouped.iterrows():
                        src_app_val = row.get('src_app')
                        src_env_val = row.get('src_env')
                        if not src_app_val or not src_env_val:
                            continue
                        if src_app_val == app_name and src_env_val == env_name:
                            continue  # Skip intra-app traffic
                        key = (src_app_val, src_env_val)
                        if key not in remote_apps_inbound:
                            remote_apps_inbound[key] = []
                        if key not in remote_apps_policy:
                            remote_apps_policy[key] = set()
                        policy = row.get('policy_decision', 'unknown')
                        remote_apps_policy[key].add(policy)
                        remote_apps_inbound[key].append({
                            "port": int(row['port']) if 'port' in row else None,
                            "proto": int(row['proto']) if 'proto' in row else None,
                            "connections": int(row['num_connections']),
                            "policy_decision": policy
                        })

            if not outbound_df.empty:
                dst_group_cols = []
                if 'dst_app' in outbound_df.columns:
                    dst_group_cols.append('dst_app')
                if 'dst_env' in outbound_df.columns:
                    dst_group_cols.append('dst_env')
                if dst_group_cols and 'port' in outbound_df.columns and 'proto' in outbound_df.columns:
                    group_cols = dst_group_cols + ['port', 'proto']
                    group_cols = [c for c in group_cols if c in outbound_df.columns]
                    outbound_grouped = outbound_df.groupby(group_cols)['num_connections'].sum().reset_index()
                    for _, row in outbound_grouped.iterrows():
                        dst_app_val = row.get('dst_app')
                        dst_env_val = row.get('dst_env')
                        if not dst_app_val or not dst_env_val:
                            continue
                        if dst_app_val == app_name and dst_env_val == env_name:
                            continue
                        key = (dst_app_val, dst_env_val)
                        if key not in remote_apps_outbound:
                            remote_apps_outbound[key] = []
                        remote_apps_outbound[key].append({
                            "port": int(row['port']) if 'port' in row else None,
                            "proto": int(row['proto']) if 'proto' in row else None,
                            "connections": int(row['num_connections'])
                        })

            logger.debug(f"Discovered {len(remote_apps_inbound)} inbound remote apps, {len(remote_apps_outbound)} outbound remote apps")

            # Classify each remote app's policy coverage
            # "already_allowed" = all flows are policy_decision=allowed
            # "newly_allowed" = at least one flow is potentially_blocked or blocked
            remote_apps_coverage = {}
            for key, decisions in remote_apps_policy.items():
                if decisions <= {'allowed'}:
                    remote_apps_coverage[key] = "already_allowed"
                else:
                    remote_apps_coverage[key] = "newly_allowed"

            already_allowed_count = sum(1 for v in remote_apps_coverage.values() if v == "already_allowed")
            newly_allowed_count = sum(1 for v in remote_apps_coverage.values() if v == "newly_allowed")

            # If skip_allowed, remove already-allowed remote apps
            skipped_already_allowed = []
            if skip_allowed:
                for key in list(remote_apps_inbound.keys()):
                    if remote_apps_coverage.get(key) == "already_allowed":
                        logger.debug(f"Skipping already-allowed remote app: app={key[0]}, env={key[1]}")
                        skipped_already_allowed.append({"app": key[0], "env": key[1]})
                        del remote_apps_inbound[key]

            # Step 6: Build the result summary
            summary = {
                "app": app_name,
                "env": env_name,
                "app_label_href": app_label.href,
                "env_label_href": env_label.href,
                "lookback_days": lookback_days,
                "skip_allowed": skip_allowed,
                "policy_coverage": {
                    "already_allowed": already_allowed_count,
                    "newly_allowed": newly_allowed_count,
                    "total_remote_apps": already_allowed_count + newly_allowed_count,
                    "description": (
                        f"{already_allowed_count} remote apps already covered by existing policy, "
                        f"{newly_allowed_count} need new rules"
                    )
                },
                "inbound_remote_apps": [
                    {
                        "app": k[0], "env": k[1],
                        "coverage": remote_apps_coverage.get(k, "unknown"),
                        "observed_ports": v
                    }
                    for k, v in sorted(remote_apps_inbound.items())
                ],
                "outbound_remote_apps": [
                    {"app": k[0], "env": k[1], "observed_ports": v}
                    for k, v in sorted(remote_apps_outbound.items())
                ],
            }
            if skipped_already_allowed:
                summary["skipped_already_allowed"] = skipped_already_allowed

            summary["selective"] = selective
            if selective:
                summary["deny_consumer"] = deny_consumer

            if dry_run:
                summary["dry_run"] = True
                if selective:
                    consumer_explain = {
                        "any": "Any (0.0.0.0/0) as consumer - deny rule only written to destination workloads (safest)",
                        "ams": "All Workloads as consumer - deny rule pushed to every managed source workload",
                        "ams_and_any": "All Workloads + Any (0.0.0.0/0) - maximum coverage for managed and unmanaged sources"
                    }
                    summary["message"] = (f"Dry run - no changes made. Selective mode with deny_consumer='{deny_consumer}': "
                        f"{consumer_explain.get(deny_consumer, '')}. "
                        "Will create allow rules for known remote apps plus a deny rule blocking all other inbound. "
                        "Rule order: allow > deny > default(allow-all). Review and run again with dry_run=false.")
                else:
                    summary["message"] = "Dry run - no changes made. Review the discovered traffic and run again with dry_run=false to create the ringfence."
                return [types.TextContent(type="text", text=json.dumps(summary, indent=2))]

            # Step 7: Check if ruleset already exists - merge if so
            existing = pce.rule_sets.get(params={"name": rs_name})
            has_intra_scope = False
            has_deny_all_inbound = False
            existing_remote_keys = set()

            if existing:
                ruleset = existing[0]
                logger.debug(f"Merging into existing ruleset: {ruleset.href}")
                summary["merged"] = True

                # Scan existing allow rules for duplicates
                # SDK returns Actor objects: Actor(actors='ams') or Actor(label=Reference(href='...'))
                def is_ams_actor(actor):
                    return hasattr(actor, 'actors') and actor.actors == 'ams'

                def get_label_href(actor):
                    if hasattr(actor, 'label') and actor.label and hasattr(actor.label, 'href'):
                        return actor.label.href
                    return None

                for rule in ruleset.rules:
                    rule_app = None
                    rule_env = None
                    is_ams_consumers = False
                    is_ams_providers = False
                    is_unscoped = getattr(rule, 'unscoped_consumers', False)

                    if rule.consumers:
                        for c in rule.consumers:
                            if is_ams_actor(c):
                                is_ams_consumers = True
                            else:
                                href = get_label_href(c)
                                if href:
                                    info = label_href_map.get(href, {})
                                    if info.get("key") == "app":
                                        rule_app = info.get("value")
                                    elif info.get("key") == "env":
                                        rule_env = info.get("value")

                    if rule.providers:
                        for p in rule.providers:
                            if is_ams_actor(p):
                                is_ams_providers = True

                    # Detect intra-scope rule: AMS->AMS, not unscoped
                    if is_ams_consumers and is_ams_providers and not is_unscoped:
                        has_intra_scope = True

                    # Detect extra-scope rule by consumer app+env
                    if rule_app and rule_env:
                        existing_remote_keys.add((rule_app, rule_env))

                # Scan existing deny rules
                try:
                    rs_href = ruleset.href
                    if '/active/' in rs_href:
                        rs_href = rs_href.replace('/active/', '/draft/')
                    resp = pce.get(f"{rs_href}/deny_rules")
                    existing_deny_rules = resp.json()
                    for dr in existing_deny_rules:
                        if not dr.get('override', False):
                            # Regular deny rule - check if it's a deny-all-inbound
                            # Consumer could be AMS, Any IP list, or both
                            is_unscoped = dr.get('unscoped_consumers', False)
                            consumers_ams = any(c.get('actors') == 'ams' for c in dr.get('consumers', []))
                            consumers_iplist = any(c.get('ip_list') for c in dr.get('consumers', []))
                            providers_ams = any(p.get('actors') == 'ams' for p in dr.get('providers', []))
                            if is_unscoped and (consumers_ams or consumers_iplist) and providers_ams:
                                has_deny_all_inbound = True
                except Exception as de:
                    logger.debug(f"Could not fetch deny_rules for merge check: {de}")

                summary["has_deny_all_inbound"] = has_deny_all_inbound

                # Remove already-covered remote apps from inbound list
                skipped = []
                for key in list(remote_apps_inbound.keys()):
                    if key in existing_remote_keys:
                        logger.debug(f"Skipping already-covered remote app: app={key[0]}, env={key[1]}")
                        skipped.append({"app": key[0], "env": key[1]})
                        del remote_apps_inbound[key]
                if skipped:
                    summary["skipped_existing_rules"] = skipped
            else:
                # Step 8: Create the ruleset scoped to [app, env]
                ruleset = RuleSet(name=rs_name, description=f"Ringfence for {app_name} ({env_name})")
                scope_labels = LabelSet(labels=[app_label, env_label])
                ruleset.scopes = [scope_labels]
                ruleset = pce.rule_sets.create(ruleset)
                logger.debug(f"Created ruleset: {ruleset.href}")
                summary["merged"] = False

            created_rules = []

            # Step 9: Create intra-scope rule if it doesn't already exist
            if not has_intra_scope:
                if all_services_href:
                    intra_services = [{"href": all_services_href}]
                else:
                    intra_services = [ServicePort(port=-1, proto=6), ServicePort(port=-1, proto=17)]

                intra_rule = Rule.build(
                    providers=[AMS],
                    consumers=[AMS],
                    ingress_services=intra_services,
                    unscoped_consumers=False
                )
                created_intra = pce.rules.create(intra_rule, parent=ruleset)
                created_rules.append({
                    "type": "intra-scope",
                    "href": created_intra.href,
                    "description": "All workloads within app can communicate on All Services",
                    "consumers": "All Workloads (in scope)",
                    "providers": "All Workloads (in scope)",
                    "services": "All Services"
                })

            # Step 10: For selective mode, create a deny rule blocking all inbound traffic
            if selective and not summary.get("has_deny_all_inbound", False):
                if all_services_href:
                    deny_services = [{"href": all_services_href}]
                else:
                    deny_services = [{"port": -1, "proto": 6}, {"port": -1, "proto": 17}]

                # Build consumers based on deny_consumer flavor
                if deny_consumer == "any":
                    deny_consumers = [{"ip_list": {"href": any_iplist_href}}]
                    consumer_desc = "Any (0.0.0.0/0) - deny written to destination only"
                elif deny_consumer == "ams":
                    deny_consumers = [{"actors": "ams"}]
                    consumer_desc = "All Workloads - deny pushed to all managed source workloads"
                elif deny_consumer == "ams_and_any":
                    deny_consumers = [{"actors": "ams"}, {"ip_list": {"href": any_iplist_href}}]
                    consumer_desc = "All Workloads + Any (0.0.0.0/0) - maximum coverage"
                else:
                    deny_consumers = [{"ip_list": {"href": any_iplist_href}}]
                    consumer_desc = "Any (0.0.0.0/0)"

                deny_payload = {
                    "enabled": True,
                    "providers": [{"actors": "ams"}],
                    "consumers": deny_consumers,
                    "ingress_services": deny_services,
                    "unscoped_consumers": True,
                    "override": False
                }

                ruleset_href = ruleset.href
                if '/active/' in ruleset_href:
                    ruleset_href = ruleset_href.replace('/active/', '/draft/')

                resp = pce.post(f"{ruleset_href}/deny_rules", json=deny_payload)
                deny_result = resp.json()
                created_rules.append({
                    "type": "deny (block all inbound)",
                    "href": deny_result.get("href", ""),
                    "description": f"Deny all inbound traffic to {app_name} ({env_name}) - selective enforcement",
                    "consumers": consumer_desc,
                    "deny_consumer_mode": deny_consumer,
                    "providers": "All Workloads (in scope)",
                    "services": "All Services"
                })
                logger.debug(f"Created deny rule for selective enforcement: {deny_result.get('href')}")

            # Step 11: Create extra-scope allow rules for each inbound remote app
            # In both standard and selective mode, known remote apps get allow rules.
            # Rule processing order: override_deny > allow > deny > default.
            # In selective mode the deny rule (step 10) catches unknown inbound,
            # but allow rules for known apps are processed first (step 3 in rule order).
            for (remote_app, remote_env), ports in sorted(remote_apps_inbound.items()):
                remote_app_labels = pce.labels.get(params={"key": "app", "value": remote_app})
                remote_env_labels = pce.labels.get(params={"key": "env", "value": remote_env})

                if not remote_app_labels or not remote_env_labels:
                    logger.warning(f"Could not find labels for remote app={remote_app}, env={remote_env}, skipping")
                    continue

                consumers = [remote_app_labels[0], remote_env_labels[0]]

                if all_services_href:
                    extra_services = [{"href": all_services_href}]
                else:
                    extra_services = [ServicePort(port=-1, proto=6), ServicePort(port=-1, proto=17)]

                extra_rule = Rule.build(
                    providers=[AMS],
                    consumers=consumers,
                    ingress_services=extra_services,
                    unscoped_consumers=True
                )
                coverage = remote_apps_coverage.get((remote_app, remote_env), "unknown")
                created_extra = pce.rules.create(extra_rule, parent=ruleset)
                created_rules.append({
                    "type": "extra-scope allow (inbound)",
                    "href": created_extra.href,
                    "description": f"Allow {remote_app} ({remote_env}) -> {app_name} ({env_name})",
                    "consumers": f"app={remote_app}, env={remote_env}",
                    "providers": "All Workloads (in scope)",
                    "services": "All Services",
                    "coverage": coverage,
                    "observed_ports": ports
                })

            # Build summary message
            extra_rules = [r for r in created_rules if r["type"] == "extra-scope allow (inbound)"]
            already_count = sum(1 for r in extra_rules if r.get("coverage") == "already_allowed")
            newly_count = sum(1 for r in extra_rules if r.get("coverage") == "newly_allowed")
            coverage_note = ""
            if already_count > 0 or newly_count > 0:
                coverage_note = (f" Policy coverage: {already_count} rules for already-allowed traffic "
                    f"(documentation), {newly_count} rules for newly-allowed traffic (filling gaps).")

            if selective:
                deny_count = sum(1 for r in created_rules if r["type"].startswith("deny"))
                allow_count = sum(1 for r in created_rules if "allow" in r["type"])
                summary["enforcement_mode"] = "selective"
                summary["message"] = (f"Selective ringfence created with {len(created_rules)} rules: "
                    f"{allow_count} allow (intra-scope + known remote apps), "
                    f"{deny_count} deny-all-inbound. "
                    f"In selective mode: allows are processed before deny, so known apps pass through "
                    f"and everything else is blocked by the deny rule.{coverage_note}")
            else:
                summary["message"] = (f"Ringfence created with {len(created_rules)} rules "
                    f"({1} intra-scope + {len(created_rules) - 1} extra-scope inbound).{coverage_note}")

            summary["ruleset"] = {
                "href": ruleset.href,
                "name": rs_name,
                "rules": created_rules
            }

            return [types.TextContent(type="text", text=json.dumps(summary, indent=2))]

        except Exception as e:
            error_msg = f"Failed to create ringfence: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

    elif name == "identify-infrastructure-services":
        logger.debug("=" * 80)
        logger.debug("IDENTIFY INFRASTRUCTURE SERVICES CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            from collections import defaultdict, deque

            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            lookback_days = arguments.get("lookback_days", 90)
            min_connections = arguments.get("min_connections", 1)
            top_n = arguments.get("top_n", 20)

            # Query all traffic
            end = datetime.now()
            start = end - timedelta(days=lookback_days)

            traffic_query = TrafficQuery.build(
                start_date=start.strftime("%Y-%m-%d"),
                end_date=end.strftime("%Y-%m-%d"),
                policy_decisions=["allowed", "potentially_blocked", "blocked"],
                max_results=100000
            )

            flows = pce.get_traffic_flows_async(
                query_name='infra-identification',
                traffic_query=traffic_query
            )
            logger.debug(f"Got {len(flows)} flows for infrastructure analysis")

            if not flows:
                return [types.TextContent(type="text", text=json.dumps({
                    "message": "No traffic flows found in the specified time range",
                    "lookback_days": lookback_days
                }, indent=2))]

            df = to_dataframe(flows)

            if df.empty or 'src_app' not in df.columns or 'dst_app' not in df.columns:
                return [types.TextContent(type="text", text=json.dumps({
                    "message": "Traffic data has no labeled app flows to analyze",
                    "total_flows": len(flows)
                }, indent=2))]

            # Build app-to-app edge list (only flows where both sides have app+env labels)
            edge_cols = ['src_app', 'src_env', 'dst_app', 'dst_env', 'num_connections']
            edges_df = df[edge_cols].dropna().copy()
            edges_df['src'] = edges_df['src_app'] + '|' + edges_df['src_env']
            edges_df['dst'] = edges_df['dst_app'] + '|' + edges_df['dst_env']

            # Remove self-loops (intra-app traffic)
            edges_df = edges_df[edges_df['src'] != edges_df['dst']]

            # Aggregate edges
            edge_agg = edges_df.groupby(['src', 'dst'])['num_connections'].sum().reset_index()

            # Apply min_connections filter
            edge_agg = edge_agg[edge_agg['num_connections'] >= min_connections]

            all_nodes = sorted(set(edge_agg['src']) | set(edge_agg['dst']))
            num_nodes = len(all_nodes)

            if num_nodes == 0:
                return [types.TextContent(type="text", text=json.dumps({
                    "message": "No app-to-app edges found after filtering",
                    "total_flows": len(flows),
                    "min_connections": min_connections
                }, indent=2))]

            # Compute degree metrics
            in_degree = {}
            out_degree = {}
            in_conn = {}
            out_conn = {}
            in_neighbors = {}
            out_neighbors = {}

            for node in all_nodes:
                ie = edge_agg[edge_agg['dst'] == node]
                oe = edge_agg[edge_agg['src'] == node]
                in_degree[node] = len(ie)
                out_degree[node] = len(oe)
                in_conn[node] = int(ie['num_connections'].sum())
                out_conn[node] = int(oe['num_connections'].sum())
                in_neighbors[node] = sorted(ie['src'].tolist())
                out_neighbors[node] = sorted(oe['dst'].tolist())

            # Betweenness centrality (Brandes algorithm on undirected graph)
            adj = defaultdict(set)
            for _, row in edge_agg.iterrows():
                adj[row['src']].add(row['dst'])
                adj[row['dst']].add(row['src'])

            betweenness = {v: 0.0 for v in all_nodes}
            for s in all_nodes:
                S = []
                P = {v: [] for v in all_nodes}
                sigma = {v: 0 for v in all_nodes}
                sigma[s] = 1
                d = {v: -1 for v in all_nodes}
                d[s] = 0
                Q = deque([s])
                while Q:
                    v = Q.popleft()
                    S.append(v)
                    for w in adj[v]:
                        if d[w] < 0:
                            Q.append(w)
                            d[w] = d[v] + 1
                        if d[w] == d[v] + 1:
                            sigma[w] += sigma[v]
                            P[w].append(v)
                delta = {v: 0.0 for v in all_nodes}
                while S:
                    w = S.pop()
                    for v in P[w]:
                        delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
                    if w != s:
                        betweenness[w] += delta[w]

            # Normalize betweenness
            if num_nodes > 2:
                norm = 1.0 / ((num_nodes - 1) * (num_nodes - 2))
                betweenness = {k: v * norm for k, v in betweenness.items()}

            # Count unmanaged sources connecting to each app
            unmanaged_df = df[df['src_app'].isna() & df['dst_app'].notna()].copy()
            unmanaged_in = {}
            if not unmanaged_df.empty:
                unmanaged_df['dst'] = unmanaged_df['dst_app'] + '|' + unmanaged_df['dst_env']
                unmanaged_in = unmanaged_df.groupby('dst')['src_ip'].nunique().to_dict()

            # Compute dual-pattern infrastructure score.
            # Two types of infra: providers (high in-degree) and consumers (high out-degree).
            # Compute both pattern scores, take the max, then apply dampening + env penalty.
            max_in = max(in_degree.values()) if in_degree else 1
            max_out = max(out_degree.values()) if out_degree else 1
            max_between = max(betweenness.values()) if betweenness else 1
            max_conn = max(in_conn[n] + out_conn[n] for n in all_nodes) if all_nodes else 1

            results = []
            for node in all_nodes:
                total_deg = in_degree[node] + out_degree[node]
                consumer_ratio = in_degree[node] / total_deg if total_deg > 0 else 0
                producer_ratio = 1.0 - consumer_ratio
                total_connections = in_conn[node] + out_conn[node]

                in_deg_score = (in_degree[node] / max_in) * 100 if max_in > 0 else 0
                out_deg_score = (out_degree[node] / max_out) * 100 if max_out > 0 else 0
                between_score = (betweenness[node] / max_between) * 100 if max_between > 0 else 0
                conn_score = (total_connections / max_conn) * 100 if max_conn > 0 else 0

                # Provider pattern: consumed by many apps (AD, DNS, shared DB)
                provider_score = (
                    (in_deg_score * 0.40) + (consumer_ratio * 100 * 0.30) +
                    (between_score * 0.25) + (conn_score * 0.05)
                )

                # Consumer pattern: connects out to many apps (monitoring, backup)
                consumer_score = (
                    (out_deg_score * 0.40) + (producer_ratio * 100 * 0.30) +
                    (between_score * 0.25) + (conn_score * 0.05)
                )

                infra_score = max(provider_score, consumer_score)
                dominant_pattern = "provider" if provider_score >= consumer_score else "consumer"

                # Mixed-traffic dampening: apps with both inbound AND outbound
                # connections are likely business apps, not infrastructure.
                # Only applies when min(in, out) > 0.
                mixed_degree = min(in_degree[node], out_degree[node])
                if mixed_degree > 0:
                    infra_score *= 1.0 / (1 + mixed_degree * 0.3)

                # Environment penalty: infrastructure services live in prod.
                # Non-production environments get a 50% score reduction.
                app, env = node.split('|', 1)
                env_lower = env.lower()
                is_prod = env_lower in ('prod', 'production')
                if not is_prod:
                    infra_score *= 0.5

                infra_score = round(infra_score, 1)

                if infra_score >= 75:
                    tier = "Core Infrastructure"
                elif infra_score >= 50:
                    tier = "Shared Service"
                else:
                    tier = "Standard Application"

                results.append({
                    "app": app,
                    "env": env,
                    "is_production": is_prod,
                    "infrastructure_score": infra_score,
                    "tier": tier,
                    "dominant_pattern": dominant_pattern,
                    "in_degree": in_degree[node],
                    "out_degree": out_degree[node],
                    "betweenness_centrality": round(betweenness[node], 4),
                    "consumer_ratio": round(consumer_ratio, 2),
                    "inbound_connections": in_conn[node],
                    "outbound_connections": out_conn[node],
                    "total_connections": total_connections,
                    "unmanaged_sources": unmanaged_in.get(node, 0),
                    "consumed_by": in_neighbors[node],
                    "consumes": out_neighbors[node],
                })

            # Sort by score descending
            results.sort(key=lambda x: x["infrastructure_score"], reverse=True)

            # Trim to top_n
            results = results[:top_n]

            # Build tier summary
            core_count = sum(1 for r in results if r["tier"] == "Core Infrastructure")
            shared_count = sum(1 for r in results if r["tier"] == "Shared Service")
            standard_count = sum(1 for r in results if r["tier"] == "Standard Application")

            output = {
                "summary": {
                    "total_flows_analyzed": len(flows),
                    "lookback_days": lookback_days,
                    "unique_apps": num_nodes,
                    "unique_app_to_app_edges": len(edge_agg),
                    "min_connections_filter": min_connections,
                    "tier_counts": {
                        "core_infrastructure": core_count,
                        "shared_service": shared_count,
                        "standard_application": standard_count
                    },
                    "scoring_methodology": (
                        "Dual-pattern scoring recognizes two types of infrastructure: "
                        "PROVIDER (AD, DNS, shared DB — consumed by many apps, high in-degree) and "
                        "CONSUMER (monitoring, backup — connects out to many apps, high out-degree). "
                        "Provider score = 40% in-degree + 30% consumer ratio + 25% betweenness + 5% volume. "
                        "Consumer score = 40% out-degree + 30% producer ratio + 25% betweenness + 5% volume. "
                        "Final score = max(provider, consumer). "
                        "Mixed-traffic dampening: score *= 1/(1 + min(in,out) * 0.3) — "
                        "apps with both significant in AND out connections are business apps, not infra. "
                        "Non-production environments receive a 50% score penalty. "
                        "Core Infrastructure >= 75, Shared Service >= 50, Standard Application < 50."
                    ),
                    "recommendation": (
                        "Start segmentation with Core Infrastructure and Shared Services — "
                        "these are consumed by many apps and must be explicitly allowed in ringfence policies. "
                        "Policy them first to avoid breaking dependent applications."
                    )
                },
                "results": results
            }

            return [types.TextContent(type="text", text=json.dumps(output, indent=2))]

        except Exception as e:
            error_msg = f"Failed to identify infrastructure services: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

    elif name == "provision-policy":
        logger.debug("=" * 80)
        logger.debug("PROVISION POLICY CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            change_description = arguments.get("change_description", "Provisioned via MCP")
            hrefs = arguments.get("hrefs")

            if hrefs:
                # Provision specific items
                payload = {
                    "update_description": change_description,
                    "change_subset": {"hrefs": hrefs}
                }
            else:
                # Get all pending changes first
                resp = pce.get("/sec_policy/pending")
                pending = resp.json()

                if not pending:
                    return [types.TextContent(type="text", text=json.dumps({
                        "message": "No pending draft changes to provision",
                        "status": "no_changes"
                    }, indent=2))]

                # Collect all pending hrefs
                pending_hrefs = []
                for item in pending:
                    if isinstance(item, dict) and 'href' in item:
                        pending_hrefs.append(item['href'])

                if not pending_hrefs:
                    return [types.TextContent(type="text", text=json.dumps({
                        "message": "No pending draft changes to provision",
                        "status": "no_changes"
                    }, indent=2))]

                payload = {
                    "update_description": change_description,
                    "change_subset": {"hrefs": pending_hrefs}
                }

            resp = pce.post("/sec_policy", json=payload)
            result = resp.json()

            return [types.TextContent(type="text", text=json.dumps({
                "message": "Policy provisioned successfully",
                "change_description": change_description,
                "result": result
            }, indent=2))]

        except Exception as e:
            error_msg = f"Failed to provision policy: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

    elif name == "compare-draft-active":
        logger.debug("=" * 80)
        logger.debug("COMPARE DRAFT ACTIVE CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            resource_type = arguments.get("resource_type", "all")

            # Get pending changes which show what differs between draft and active
            resp = pce.get("/sec_policy/pending")
            pending = resp.json()

            if not pending:
                return [types.TextContent(type="text", text=json.dumps({
                    "message": "No differences between draft and active policy",
                    "status": "in_sync"
                }, indent=2))]

            changes = {
                "created": [],
                "updated": [],
                "deleted": []
            }

            for item in pending:
                if not isinstance(item, dict):
                    continue

                href = item.get('href', '')
                change_type = item.get('change_type', 'unknown')
                item_type = 'unknown'

                if '/rule_sets/' in href:
                    item_type = 'rule_sets'
                elif '/ip_lists/' in href:
                    item_type = 'ip_lists'
                elif '/services/' in href:
                    item_type = 'services'
                elif '/labels/' in href:
                    item_type = 'labels'

                if resource_type != "all" and item_type != resource_type:
                    continue

                change_info = {
                    "href": href,
                    "type": item_type,
                    "name": item.get('name', ''),
                }

                if change_type == 'create':
                    changes["created"].append(change_info)
                elif change_type == 'update':
                    changes["updated"].append(change_info)
                elif change_type == 'delete':
                    changes["deleted"].append(change_info)
                else:
                    changes.setdefault("other", []).append({**change_info, "change_type": change_type})

            summary = {
                "total_pending_changes": len(pending),
                "filter": resource_type,
                "created_count": len(changes["created"]),
                "updated_count": len(changes["updated"]),
                "deleted_count": len(changes["deleted"]),
                "changes": changes
            }

            return [types.TextContent(type="text", text=json.dumps(summary, indent=2))]

        except Exception as e:
            error_msg = f"Failed to compare draft vs active: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

    elif name == "enforcement-readiness":
        logger.debug("=" * 80)
        logger.debug("ENFORCEMENT READINESS CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            app_name = arguments["app_name"]
            env_name = arguments["env_name"]
            lookback_days = arguments.get("lookback_days", 30)

            # Find labels
            app_labels = pce.labels.get(params={"key": "app", "value": app_name})
            if not app_labels:
                return [types.TextContent(type="text", text=json.dumps({"error": f"App label '{app_name}' not found"}))]
            app_label = app_labels[0]

            env_labels = pce.labels.get(params={"key": "env", "value": env_name})
            if not env_labels:
                return [types.TextContent(type="text", text=json.dumps({"error": f"Env label '{env_name}' not found"}))]
            env_label = env_labels[0]

            # Get workloads for this app+env
            workloads = pce.workloads.get(params={
                "labels": json.dumps([app_label.href, env_label.href]),
                "max_results": 10000,
                "include": "labels"
            })

            # Analyze enforcement modes
            enforcement_modes = {}
            for w in workloads:
                mode = getattr(w, 'enforcement_mode', 'unknown') or 'unknown'
                enforcement_modes[mode] = enforcement_modes.get(mode, 0) + 1

            # Query traffic flows
            start_date = (datetime.now() - timedelta(days=lookback_days)).strftime('%Y-%m-%d')
            end_date = datetime.now().strftime('%Y-%m-%d')

            app_filter = TrafficQueryFilter(label=Reference(href=app_label.href))
            env_filter = TrafficQueryFilter(label=Reference(href=env_label.href))

            # Inbound traffic
            traffic_query = TrafficQuery.build(
                start_date=start_date,
                end_date=end_date,
                include_sources=[[]],
                include_destinations=[[app_filter, env_filter]],
                policy_decisions=["allowed", "potentially_blocked", "blocked"],
                max_results=MCP_BUG_MAX_RESULTS,
                query_name='readiness-inbound'
            )
            inbound_flows = pce.get_traffic_flows_async(query_name='readiness-inbound', traffic_query=traffic_query)

            # Outbound traffic
            traffic_query_out = TrafficQuery.build(
                start_date=start_date,
                end_date=end_date,
                include_sources=[[app_filter, env_filter]],
                include_destinations=[[]],
                policy_decisions=["allowed", "potentially_blocked", "blocked"],
                max_results=MCP_BUG_MAX_RESULTS,
                query_name='readiness-outbound'
            )
            outbound_flows = pce.get_traffic_flows_async(query_name='readiness-outbound', traffic_query=traffic_query_out)

            inbound_df = to_dataframe(inbound_flows)
            outbound_df = to_dataframe(outbound_flows)

            # Analyze policy decisions
            policy_stats = {"allowed": 0, "potentially_blocked": 0, "blocked": 0, "unknown": 0}
            total_flows = 0

            for df in [inbound_df, outbound_df]:
                if not df.empty and 'policy_decision' in df.columns:
                    for decision, count in df['policy_decision'].value_counts().items():
                        policy_stats[decision] = policy_stats.get(decision, 0) + count
                        total_flows += count

            # Identify unique remote apps and their coverage
            remote_apps_covered = set()
            remote_apps_uncovered = set()

            if not inbound_df.empty and 'src_app' in inbound_df.columns and 'src_env' in inbound_df.columns:
                for _, row in inbound_df.iterrows():
                    if pd.notna(row.get('src_app')) and pd.notna(row.get('src_env')):
                        key = (row['src_app'], row['src_env'])
                        if key == (app_name, env_name):
                            continue
                        if row.get('policy_decision') == 'allowed':
                            remote_apps_covered.add(key)
                        else:
                            remote_apps_uncovered.add(key)

            # Check for existing rulesets
            rulesets = pce.rule_sets.get(params={"name": f"RF-{app_name}-{env_name}"})
            has_ringfence = len(rulesets) > 0

            # Calculate readiness score (0-100)
            readiness_score = 0
            recommendations = []

            # Factor 1: Policy coverage (40 points)
            if total_flows > 0:
                coverage_ratio = policy_stats.get("allowed", 0) / total_flows
                readiness_score += coverage_ratio * 40
                if coverage_ratio < 0.5:
                    recommendations.append("Less than 50% of traffic is covered by policy — create rules for observed traffic patterns")
                elif coverage_ratio < 0.9:
                    recommendations.append("Some traffic is not yet covered — review potentially_blocked flows and add rules")
            else:
                recommendations.append("No traffic flows found — verify workloads are online and sending data")

            # Factor 2: Ringfence exists (20 points)
            if has_ringfence:
                readiness_score += 20
            else:
                recommendations.append("No ringfence ruleset found — run create-ringfence to create app-level segmentation")

            # Factor 3: Enforcement mode (20 points)
            if enforcement_modes.get('full', 0) == len(workloads) and len(workloads) > 0:
                readiness_score += 20
            elif enforcement_modes.get('selective', 0) > 0:
                readiness_score += 10
                recommendations.append("Some workloads in selective mode — consider moving to full enforcement after validation")
            elif enforcement_modes.get('visibility_only', 0) > 0:
                readiness_score += 5
                recommendations.append("Workloads in visibility_only — move to selective or full enforcement when policies are ready")
            else:
                recommendations.append("No enforcement configured — start with visibility_only, then selective, then full")

            # Factor 4: No blocked traffic (10 points)
            if policy_stats.get("blocked", 0) == 0:
                readiness_score += 10
            else:
                recommendations.append(f"{policy_stats['blocked']} flows are currently blocked — investigate if these are intentional or need new rules")

            # Factor 5: All remote apps covered (10 points)
            uncovered_only = remote_apps_uncovered - remote_apps_covered
            if not uncovered_only:
                readiness_score += 10
            else:
                recommendations.append(f"{len(uncovered_only)} remote apps have uncovered traffic — review and create allow rules")

            readiness_score = round(readiness_score, 1)

            if readiness_score >= 80:
                readiness_level = "Ready for enforcement"
            elif readiness_score >= 50:
                readiness_level = "Partially ready — address recommendations"
            else:
                readiness_level = "Not ready — significant policy gaps"

            result = {
                "app": app_name,
                "env": env_name,
                "readiness_score": readiness_score,
                "readiness_level": readiness_level,
                "workloads": {
                    "total": len(workloads),
                    "enforcement_modes": enforcement_modes
                },
                "traffic_analysis": {
                    "lookback_days": lookback_days,
                    "total_flows": total_flows,
                    "policy_decisions": policy_stats,
                    "coverage_percentage": round((policy_stats.get("allowed", 0) / total_flows * 100) if total_flows > 0 else 0, 1)
                },
                "remote_apps": {
                    "covered": [{"app": a, "env": e} for a, e in sorted(remote_apps_covered)],
                    "uncovered": [{"app": a, "env": e} for a, e in sorted(uncovered_only)],
                },
                "has_ringfence": has_ringfence,
                "recommendations": recommendations
            }

            return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

        except Exception as e:
            error_msg = f"Failed to assess enforcement readiness: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

    elif name == "ringfence-batch":
        logger.debug("=" * 80)
        logger.debug("RINGFENCE BATCH CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            apps = arguments["apps"]
            auto_order = arguments.get("auto_order", False)
            dry_run = arguments.get("dry_run", False)
            lookback_days = arguments.get("lookback_days", 30)

            if auto_order:
                # Use infrastructure identification to order apps
                infra_result = await handle_call_tool("identify-infrastructure-services", {
                    "lookback_days": lookback_days,
                    "top_n": 1000
                })
                # Parse the result to build an ordering map
                try:
                    infra_data = json.loads(infra_result[0].text)
                    score_map = {}
                    for r in infra_data.get("results", []):
                        score_map[(r["app"], r["env"])] = r["infrastructure_score"]
                except (json.JSONDecodeError, KeyError, IndexError):
                    score_map = {}

                # Sort apps: infrastructure (higher score) first
                apps.sort(key=lambda a: score_map.get((a["app_name"], a["env_name"]), 0), reverse=True)

            results = []
            for app in apps:
                rf_args = {
                    "app_name": app["app_name"],
                    "env_name": app["env_name"],
                    "lookback_days": lookback_days,
                    "dry_run": dry_run,
                    "selective": app.get("selective", False)
                }

                try:
                    rf_result = await handle_call_tool("create-ringfence", rf_args)
                    result_data = json.loads(rf_result[0].text)
                    results.append({
                        "app": app["app_name"],
                        "env": app["env_name"],
                        "status": "success",
                        "result": result_data
                    })
                except Exception as app_err:
                    results.append({
                        "app": app["app_name"],
                        "env": app["env_name"],
                        "status": "error",
                        "error": str(app_err)
                    })

            success_count = sum(1 for r in results if r["status"] == "success")
            error_count = sum(1 for r in results if r["status"] == "error")

            output = {
                "summary": {
                    "total_apps": len(apps),
                    "successful": success_count,
                    "errors": error_count,
                    "dry_run": dry_run,
                    "auto_ordered": auto_order
                },
                "results": results
            }

            return [types.TextContent(type="text", text=json.dumps(output, indent=2))]

        except Exception as e:
            error_msg = f"Failed batch ringfence: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

    elif name == "get-workload-enforcement-status":
        logger.debug("=" * 80)
        logger.debug("GET WORKLOAD ENFORCEMENT STATUS CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            params = {"include": "labels", "max_results": 10000}

            # Build label filter if app/env specified
            filter_labels = []
            if arguments.get("app_name"):
                app_labels = pce.labels.get(params={"key": "app", "value": arguments["app_name"]})
                if app_labels:
                    filter_labels.append(app_labels[0].href)
            if arguments.get("env_name"):
                env_labels = pce.labels.get(params={"key": "env", "value": arguments["env_name"]})
                if env_labels:
                    filter_labels.append(env_labels[0].href)
            if filter_labels:
                params["labels"] = json.dumps(filter_labels)

            workloads = pce.workloads.get(params=params)

            # Build label href map for resolution
            label_href_map = {}
            for l in pce.labels.get(params={'max_results': 10000}):
                label_href_map[l.href] = {"key": l.key, "value": l.value}

            # Group by app+env
            app_env_groups = {}
            for w in workloads:
                app_val = None
                env_val = None
                if hasattr(w, 'labels') and w.labels:
                    for l in w.labels:
                        info = label_href_map.get(l.href, {})
                        if info.get("key") == "app":
                            app_val = info.get("value")
                        elif info.get("key") == "env":
                            env_val = info.get("value")

                key = f"{app_val or 'unlabeled'}|{env_val or 'unlabeled'}"
                if key not in app_env_groups:
                    app_env_groups[key] = {"app": app_val, "env": env_val, "modes": {}, "workloads": []}

                mode = getattr(w, 'enforcement_mode', 'unknown') or 'unknown'
                app_env_groups[key]["modes"][mode] = app_env_groups[key]["modes"].get(mode, 0) + 1
                app_env_groups[key]["workloads"].append({
                    "name": w.name or w.hostname or "unnamed",
                    "href": w.href,
                    "enforcement_mode": mode,
                    "online": getattr(w, 'online', None)
                })

            # Identify mixed enforcement states
            mixed_apps = []
            for key, group in app_env_groups.items():
                if len(group["modes"]) > 1:
                    mixed_apps.append({
                        "app": group["app"],
                        "env": group["env"],
                        "modes": group["modes"]
                    })

            # Global mode summary
            global_modes = {}
            for w in workloads:
                mode = getattr(w, 'enforcement_mode', 'unknown') or 'unknown'
                global_modes[mode] = global_modes.get(mode, 0) + 1

            # Format app groups (without individual workload details to keep output manageable)
            app_summaries = []
            for key, group in sorted(app_env_groups.items()):
                app_summaries.append({
                    "app": group["app"],
                    "env": group["env"],
                    "workload_count": sum(group["modes"].values()),
                    "enforcement_modes": group["modes"],
                    "is_mixed": len(group["modes"]) > 1
                })

            result = {
                "total_workloads": len(workloads),
                "global_enforcement_modes": global_modes,
                "app_groups": app_summaries,
                "mixed_enforcement_apps": mixed_apps,
                "mixed_count": len(mixed_apps)
            }

            return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

        except Exception as e:
            error_msg = f"Failed to get enforcement status: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

    elif name == "get-policy-coverage-report":
        logger.debug("=" * 80)
        logger.debug("GET POLICY COVERAGE REPORT CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            app_name = arguments["app_name"]
            env_name = arguments["env_name"]
            lookback_days = arguments.get("lookback_days", 30)

            app_labels = pce.labels.get(params={"key": "app", "value": app_name})
            if not app_labels:
                return [types.TextContent(type="text", text=json.dumps({"error": f"App label '{app_name}' not found"}))]
            app_label = app_labels[0]

            env_labels = pce.labels.get(params={"key": "env", "value": env_name})
            if not env_labels:
                return [types.TextContent(type="text", text=json.dumps({"error": f"Env label '{env_name}' not found"}))]
            env_label = env_labels[0]

            start_date = (datetime.now() - timedelta(days=lookback_days)).strftime('%Y-%m-%d')
            end_date = datetime.now().strftime('%Y-%m-%d')

            app_filter = TrafficQueryFilter(label=Reference(href=app_label.href))
            env_filter = TrafficQueryFilter(label=Reference(href=env_label.href))

            # Query inbound traffic with all policy decisions
            traffic_query = TrafficQuery.build(
                start_date=start_date,
                end_date=end_date,
                include_sources=[[]],
                include_destinations=[[app_filter, env_filter]],
                policy_decisions=["allowed", "potentially_blocked", "blocked"],
                max_results=MCP_BUG_MAX_RESULTS,
                query_name='coverage-inbound'
            )
            inbound_flows = pce.get_traffic_flows_async(query_name='coverage-inbound', traffic_query=traffic_query)

            # Query outbound
            traffic_query_out = TrafficQuery.build(
                start_date=start_date,
                end_date=end_date,
                include_sources=[[app_filter, env_filter]],
                include_destinations=[[]],
                policy_decisions=["allowed", "potentially_blocked", "blocked"],
                max_results=MCP_BUG_MAX_RESULTS,
                query_name='coverage-outbound'
            )
            outbound_flows = pce.get_traffic_flows_async(query_name='coverage-outbound', traffic_query=traffic_query_out)

            inbound_df = to_dataframe(inbound_flows)
            outbound_df = to_dataframe(outbound_flows)

            # Analyze by policy decision
            def analyze_coverage(df, direction):
                if df.empty:
                    return {"total_flows": 0, "by_decision": {}, "uncovered_services": [], "uncovered_apps": []}

                total = len(df)
                by_decision = {}
                if 'policy_decision' in df.columns:
                    by_decision = df['policy_decision'].value_counts().to_dict()
                    by_decision = {k: int(v) for k, v in by_decision.items()}

                # Find uncovered (potentially_blocked or blocked) services
                uncovered_services = []
                uncovered_apps = []
                if 'policy_decision' in df.columns:
                    uncovered = df[df['policy_decision'].isin(['potentially_blocked', 'blocked'])]
                    if not uncovered.empty:
                        # Group by port/proto
                        if 'port' in uncovered.columns and 'proto' in uncovered.columns:
                            svc_group = uncovered.groupby(['port', 'proto'])['num_connections'].sum().reset_index()
                            for _, row in svc_group.iterrows():
                                uncovered_services.append({
                                    "port": int(row['port']),
                                    "proto": int(row['proto']),
                                    "connections": int(row['num_connections'])
                                })
                        # Group by remote app
                        remote_col = 'src_app' if direction == 'inbound' else 'dst_app'
                        remote_env_col = 'src_env' if direction == 'inbound' else 'dst_env'
                        if remote_col in uncovered.columns and remote_env_col in uncovered.columns:
                            app_group = uncovered.groupby([remote_col, remote_env_col])['num_connections'].sum().reset_index()
                            for _, row in app_group.iterrows():
                                if pd.notna(row[remote_col]) and pd.notna(row[remote_env_col]):
                                    uncovered_apps.append({
                                        "app": row[remote_col],
                                        "env": row[remote_env_col],
                                        "connections": int(row['num_connections'])
                                    })

                covered = by_decision.get('allowed', 0)
                return {
                    "total_flows": total,
                    "by_decision": by_decision,
                    "coverage_percentage": round(covered / total * 100, 1) if total > 0 else 0,
                    "uncovered_services": sorted(uncovered_services, key=lambda x: x['connections'], reverse=True),
                    "uncovered_apps": sorted(uncovered_apps, key=lambda x: x['connections'], reverse=True)
                }

            inbound_coverage = analyze_coverage(inbound_df, 'inbound')
            outbound_coverage = analyze_coverage(outbound_df, 'outbound')

            total_flows = inbound_coverage["total_flows"] + outbound_coverage["total_flows"]
            total_allowed = inbound_coverage["by_decision"].get("allowed", 0) + outbound_coverage["by_decision"].get("allowed", 0)
            overall_coverage = round(total_allowed / total_flows * 100, 1) if total_flows > 0 else 0

            result = {
                "app": app_name,
                "env": env_name,
                "lookback_days": lookback_days,
                "overall_coverage_percentage": overall_coverage,
                "total_flows": total_flows,
                "total_allowed": total_allowed,
                "inbound": inbound_coverage,
                "outbound": outbound_coverage,
                "recommendation": (
                    "Full coverage — ready for enforcement" if overall_coverage >= 95
                    else "High coverage — review remaining gaps before enforcement" if overall_coverage >= 80
                    else "Moderate coverage — create rules for uncovered traffic" if overall_coverage >= 50
                    else "Low coverage — significant policy gaps exist, start with ringfencing"
                )
            }

            return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

        except Exception as e:
            error_msg = f"Failed to generate policy coverage report: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

    elif name == "find-unmanaged-traffic":
        logger.debug("=" * 80)
        logger.debug("FIND UNMANAGED TRAFFIC CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            lookback_days = arguments.get("lookback_days", 30)
            direction = arguments.get("direction", "both")
            min_connections = arguments.get("min_connections", 1)
            top_n = arguments.get("top_n", 50)

            start_date = (datetime.now() - timedelta(days=lookback_days)).strftime('%Y-%m-%d')
            end_date = datetime.now().strftime('%Y-%m-%d')

            traffic_query = TrafficQuery.build(
                start_date=start_date,
                end_date=end_date,
                policy_decisions=["allowed", "potentially_blocked", "blocked"],
                max_results=MCP_BUG_MAX_RESULTS,
                query_name='unmanaged-traffic'
            )

            flows = pce.get_traffic_flows_async(query_name='unmanaged-traffic', traffic_query=traffic_query)
            df = to_dataframe(flows)

            if df.empty:
                return [types.TextContent(type="text", text=json.dumps({
                    "message": "No traffic flows found", "lookback_days": lookback_days
                }, indent=2))]

            results = {"unmanaged_sources": [], "unmanaged_destinations": []}

            # Find traffic from unmanaged sources (no src_app label) to managed destinations
            if direction in ("inbound", "both"):
                if 'src_app' in df.columns and 'dst_app' in df.columns:
                    unmanaged_src = df[df['src_app'].isna() & df['dst_app'].notna()].copy()
                    if not unmanaged_src.empty:
                        group_cols = ['src_ip']
                        if 'dst_app' in unmanaged_src.columns:
                            group_cols.append('dst_app')
                        if 'dst_env' in unmanaged_src.columns:
                            group_cols.append('dst_env')
                        if 'port' in unmanaged_src.columns:
                            group_cols.append('port')
                        if 'proto' in unmanaged_src.columns:
                            group_cols.append('proto')

                        grouped = unmanaged_src.groupby(group_cols)['num_connections'].sum().reset_index()
                        grouped = grouped[grouped['num_connections'] >= min_connections]
                        grouped = grouped.sort_values('num_connections', ascending=False).head(top_n)

                        for _, row in grouped.iterrows():
                            entry = {
                                "src_ip": row.get('src_ip', ''),
                                "dst_app": row.get('dst_app', ''),
                                "dst_env": row.get('dst_env', ''),
                                "port": int(row['port']) if 'port' in row and pd.notna(row['port']) else None,
                                "proto": int(row['proto']) if 'proto' in row and pd.notna(row['proto']) else None,
                                "connections": int(row['num_connections'])
                            }
                            results["unmanaged_sources"].append(entry)

            # Find traffic to unmanaged destinations (no dst_app label) from managed sources
            if direction in ("outbound", "both"):
                if 'src_app' in df.columns and 'dst_app' in df.columns:
                    unmanaged_dst = df[df['dst_app'].isna() & df['src_app'].notna()].copy()
                    if not unmanaged_dst.empty:
                        group_cols = ['dst_ip']
                        if 'src_app' in unmanaged_dst.columns:
                            group_cols.append('src_app')
                        if 'src_env' in unmanaged_dst.columns:
                            group_cols.append('src_env')
                        if 'port' in unmanaged_dst.columns:
                            group_cols.append('port')
                        if 'proto' in unmanaged_dst.columns:
                            group_cols.append('proto')

                        grouped = unmanaged_dst.groupby(group_cols)['num_connections'].sum().reset_index()
                        grouped = grouped[grouped['num_connections'] >= min_connections]
                        grouped = grouped.sort_values('num_connections', ascending=False).head(top_n)

                        for _, row in grouped.iterrows():
                            entry = {
                                "dst_ip": row.get('dst_ip', ''),
                                "src_app": row.get('src_app', ''),
                                "src_env": row.get('src_env', ''),
                                "port": int(row['port']) if 'port' in row and pd.notna(row['port']) else None,
                                "proto": int(row['proto']) if 'proto' in row and pd.notna(row['proto']) else None,
                                "connections": int(row['num_connections'])
                            }
                            results["unmanaged_destinations"].append(entry)

            result = {
                "lookback_days": lookback_days,
                "direction_filter": direction,
                "min_connections": min_connections,
                "unmanaged_source_count": len(results["unmanaged_sources"]),
                "unmanaged_destination_count": len(results["unmanaged_destinations"]),
                "unmanaged_sources": results["unmanaged_sources"],
                "unmanaged_destinations": results["unmanaged_destinations"],
                "recommendation": (
                    "Unmanaged traffic represents policy blind spots. Consider: "
                    "1) Creating IP lists for known external services, "
                    "2) Deploying VEN agents on unmanaged workloads, "
                    "3) Adding rules for legitimate unmanaged traffic sources."
                )
            }

            return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

        except Exception as e:
            error_msg = f"Failed to find unmanaged traffic: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

    elif name == "detect-lateral-movement-paths":
        logger.debug("=" * 80)
        logger.debug("DETECT LATERAL MOVEMENT PATHS CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            from collections import defaultdict, deque

            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            lookback_days = arguments.get("lookback_days", 30)
            max_hops = arguments.get("max_hops", 4)
            start_app = arguments.get("app_name")
            start_env = arguments.get("env_name")

            start_date = (datetime.now() - timedelta(days=lookback_days)).strftime('%Y-%m-%d')
            end_date = datetime.now().strftime('%Y-%m-%d')

            traffic_query = TrafficQuery.build(
                start_date=start_date,
                end_date=end_date,
                policy_decisions=["allowed", "potentially_blocked", "blocked"],
                max_results=100000,
                query_name='lateral-movement'
            )

            flows = pce.get_traffic_flows_async(query_name='lateral-movement', traffic_query=traffic_query)
            df = to_dataframe(flows)

            if df.empty or 'src_app' not in df.columns or 'dst_app' not in df.columns:
                return [types.TextContent(type="text", text=json.dumps({
                    "message": "No labeled traffic flows found for lateral movement analysis",
                    "lookback_days": lookback_days
                }, indent=2))]

            # Build directed graph
            edges_df = df[['src_app', 'src_env', 'dst_app', 'dst_env', 'num_connections']].dropna().copy()
            edges_df['src'] = edges_df['src_app'] + '|' + edges_df['src_env']
            edges_df['dst'] = edges_df['dst_app'] + '|' + edges_df['dst_env']
            edges_df = edges_df[edges_df['src'] != edges_df['dst']]

            edge_agg = edges_df.groupby(['src', 'dst'])['num_connections'].sum().reset_index()

            # Build adjacency list (directed)
            adj = defaultdict(set)
            for _, row in edge_agg.iterrows():
                adj[row['src']].add(row['dst'])

            all_nodes = sorted(set(edge_agg['src']) | set(edge_agg['dst']))

            # Find bridge nodes (articulation points in undirected version)
            # These are nodes whose removal disconnects the graph
            undirected_adj = defaultdict(set)
            for _, row in edge_agg.iterrows():
                undirected_adj[row['src']].add(row['dst'])
                undirected_adj[row['dst']].add(row['src'])

            # Tarjan's bridge-finding algorithm
            visited = set()
            disc = {}
            low = {}
            parent = {}
            bridges = []
            articulation_points = set()
            timer = [0]

            def dfs_ap(u):
                children = 0
                visited.add(u)
                disc[u] = low[u] = timer[0]
                timer[0] += 1

                for v in undirected_adj[u]:
                    if v not in visited:
                        children += 1
                        parent[v] = u
                        dfs_ap(v)
                        low[u] = min(low[u], low[v])

                        # u is an articulation point if:
                        if parent.get(u) is None and children > 1:
                            articulation_points.add(u)
                        if parent.get(u) is not None and low[v] >= disc[u]:
                            articulation_points.add(u)
                    elif v != parent.get(u):
                        low[u] = min(low[u], disc[v])

            for node in all_nodes:
                if node not in visited:
                    parent[node] = None
                    dfs_ap(node)

            # BFS to find reachable paths from starting node(s)
            paths_from_start = []
            if start_app:
                start_node = f"{start_app}|{start_env}" if start_env else None
                if not start_node:
                    # Find all envs for this app
                    start_nodes = [n for n in all_nodes if n.startswith(f"{start_app}|")]
                else:
                    start_nodes = [start_node] if start_node in adj else []

                for sn in start_nodes:
                    # BFS up to max_hops
                    queue = deque([(sn, [sn])])
                    seen = {sn}
                    while queue:
                        current, path = queue.popleft()
                        if len(path) > max_hops + 1:
                            continue
                        for neighbor in adj.get(current, []):
                            if neighbor not in seen:
                                new_path = path + [neighbor]
                                paths_from_start.append(new_path)
                                seen.add(neighbor)
                                queue.append((neighbor, new_path))

            # Compute reach (how many nodes each node can reach)
            reach = {}
            for node in all_nodes:
                visited_bfs = set()
                queue = deque([node])
                visited_bfs.add(node)
                while queue:
                    current = queue.popleft()
                    for neighbor in adj.get(current, []):
                        if neighbor not in visited_bfs:
                            visited_bfs.add(neighbor)
                            queue.append(neighbor)
                reach[node] = len(visited_bfs) - 1  # exclude self

            # High-risk nodes: articulation points sorted by reach
            high_risk_nodes = []
            for node in sorted(articulation_points, key=lambda n: reach.get(n, 0), reverse=True):
                app, env = node.split('|', 1)
                high_risk_nodes.append({
                    "app": app,
                    "env": env,
                    "is_articulation_point": True,
                    "reachable_apps": reach.get(node, 0),
                    "direct_connections_out": len(adj.get(node, [])),
                    "direct_connections_in": sum(1 for n in all_nodes if node in adj.get(n, set()))
                })

            # Top reach nodes (even if not articulation points)
            top_reach = []
            for node in sorted(all_nodes, key=lambda n: reach.get(n, 0), reverse=True)[:20]:
                app, env = node.split('|', 1)
                top_reach.append({
                    "app": app,
                    "env": env,
                    "reachable_apps": reach.get(node, 0),
                    "is_bridge_node": node in articulation_points
                })

            result = {
                "lookback_days": lookback_days,
                "total_apps": len(all_nodes),
                "total_edges": len(edge_agg),
                "articulation_points": len(articulation_points),
                "high_risk_bridge_nodes": high_risk_nodes[:10],
                "top_reachable_nodes": top_reach,
            }

            if start_app:
                result["paths_from"] = start_app + (f"|{start_env}" if start_env else "")
                result["max_hops"] = max_hops
                result["paths"] = [
                    {"path": p, "hops": len(p) - 1}
                    for p in sorted(paths_from_start, key=lambda x: len(x), reverse=True)[:50]
                ]

            result["recommendation"] = (
                "Bridge nodes (articulation points) are critical lateral movement risks — "
                "if compromised, they provide access to otherwise disconnected app groups. "
                "Prioritize ringfencing these apps and applying strict segmentation policies. "
                "Apps with high reachability should have minimal necessary connectivity."
            )

            return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

        except Exception as e:
            error_msg = f"Failed to detect lateral movement paths: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

    elif name == "compliance-check":
        logger.debug("=" * 80)
        logger.debug("COMPLIANCE CHECK CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            framework = arguments.get("framework", "general")
            app_name = arguments.get("app_name")
            env_name = arguments.get("env_name")
            lookback_days = arguments.get("lookback_days", 30)

            # Define compliance checks per framework
            framework_checks = {
                "pci-dss": {
                    "name": "PCI-DSS",
                    "checks": [
                        {"id": "PCI-1.3", "name": "Restrict inbound traffic to CDE", "description": "Inbound traffic to cardholder data environment must be explicitly allowed"},
                        {"id": "PCI-1.4", "name": "Restrict outbound traffic from CDE", "description": "Outbound traffic from CDE must be explicitly authorized"},
                        {"id": "PCI-2.1", "name": "No default passwords", "description": "Change vendor-supplied defaults (check for common admin ports)"},
                        {"id": "PCI-6.1", "name": "Segment CDE from non-CDE", "description": "CDE must be segmented from non-CDE networks"},
                        {"id": "PCI-7.1", "name": "Restrict access by business need", "description": "Limit access to system components to only those required"},
                    ],
                    "high_risk_ports": [3389, 22, 23, 445, 1433, 3306, 5432, 1521],
                },
                "nist": {
                    "name": "NIST 800-53",
                    "checks": [
                        {"id": "AC-4", "name": "Information flow enforcement", "description": "Enforce approved authorizations for controlling information flow"},
                        {"id": "SC-7", "name": "Boundary protection", "description": "Monitor and control communications at external boundaries and key internal boundaries"},
                        {"id": "CM-7", "name": "Least functionality", "description": "Configure to provide only essential capabilities — no unnecessary ports or services"},
                        {"id": "SI-4", "name": "System monitoring", "description": "Monitor for unauthorized network connections and traffic"},
                    ],
                    "high_risk_ports": [3389, 22, 23, 445, 135, 139, 1433, 3306, 5432],
                },
                "cis": {
                    "name": "CIS Controls",
                    "checks": [
                        {"id": "CIS-9", "name": "Network access control", "description": "Manage network access control and micro-segmentation"},
                        {"id": "CIS-12", "name": "Network infrastructure management", "description": "Establish network segmentation with security boundaries"},
                        {"id": "CIS-13", "name": "Network monitoring and defense", "description": "Operate processes to detect network-based threats"},
                    ],
                    "high_risk_ports": [3389, 22, 23, 445, 135, 139, 21, 69],
                },
                "dora": {
                    "name": "DORA (Digital Operational Resilience Act)",
                    "checks": [
                        {"id": "DORA-9.2", "name": "Network access restriction", "description": "Implement policies to restrict network access (Article 9.2)"},
                        {"id": "DORA-9.3", "name": "Immediate isolation capability", "description": "Design network to allow immediate severing/isolation of affected systems (Article 9.3)"},
                        {"id": "DORA-8.1", "name": "ICT asset identification", "description": "Identify and document all ICT-supported business functions and assets (Article 8.1)"},
                        {"id": "DORA-10.1", "name": "Anomaly detection", "description": "Detect anomalous activities and ICT incidents (Article 10.1)"},
                        {"id": "DORA-25.1", "name": "Resilience testing", "description": "Perform vulnerability and network security assessments (Article 25.1)"},
                    ],
                    "high_risk_ports": [3389, 22, 23, 445, 135, 139, 1433, 3306, 5432, 1521, 27017, 6379],
                },
                "iso-27001": {
                    "name": "ISO 27001:2022",
                    "checks": [
                        {"id": "A.8.22", "name": "Network segregation", "description": "Groups of information services, users, and systems shall be segregated"},
                        {"id": "A.8.20", "name": "Networks security", "description": "Secure networks including mechanisms for filtering traffic"},
                        {"id": "A.5.9", "name": "Asset inventory", "description": "Maintain inventory of information and associated assets"},
                        {"id": "A.8.26", "name": "Application security requirements", "description": "Security requirements identified when developing/acquiring applications"},
                    ],
                    "high_risk_ports": [3389, 22, 23, 445, 135, 139, 1433, 3306, 5432, 21],
                },
                "swift-csp": {
                    "name": "SWIFT Customer Security Programme",
                    "checks": [
                        {"id": "SWIFT-1.1", "name": "SWIFT environment protection", "description": "Protect SWIFT infrastructure from general IT environment"},
                        {"id": "SWIFT-1.4", "name": "Internet access restriction", "description": "SWIFT-connected systems must not have direct internet access"},
                        {"id": "SWIFT-2.1", "name": "Internal data flow security", "description": "Ensure confidentiality and integrity of data flows between SWIFT components"},
                        {"id": "SWIFT-5.1", "name": "Logical access control", "description": "Enforce least-privilege access to SWIFT systems"},
                        {"id": "SWIFT-6.4", "name": "Logging and monitoring", "description": "Record and monitor security events in the SWIFT secure zone"},
                    ],
                    "high_risk_ports": [3389, 22, 23, 445, 135, 139, 21, 80, 1433, 3306, 5432],
                },
                "hipaa": {
                    "name": "HIPAA Security Rule",
                    "checks": [
                        {"id": "HIPAA-164.312(a)", "name": "Access control", "description": "Implement technical policies to allow access only to authorized persons/software"},
                        {"id": "HIPAA-164.312(b)", "name": "Audit controls", "description": "Implement mechanisms to record and examine activity in systems containing ePHI"},
                        {"id": "HIPAA-164.312(e)", "name": "Transmission security", "description": "Guard against unauthorized access to ePHI during transmission"},
                        {"id": "HIPAA-164.308(a)(1)", "name": "Security management process", "description": "Prevent, detect, contain, and correct security violations"},
                    ],
                    "high_risk_ports": [3389, 22, 23, 445, 135, 139, 1433, 3306, 5432, 1521, 21, 80],
                },
                "general": {
                    "name": "General Security Best Practices",
                    "checks": [
                        {"id": "SEG-1", "name": "Application segmentation", "description": "Apps should have ringfence policies limiting lateral movement"},
                        {"id": "SEG-2", "name": "Enforcement mode", "description": "Workloads should not be in idle or visibility_only mode in production"},
                        {"id": "SEG-3", "name": "High-risk port exposure", "description": "Sensitive ports (RDP, SSH, DB) should have explicit allow rules only"},
                        {"id": "SEG-4", "name": "Policy coverage", "description": "Traffic should be covered by explicit policy, not relying on default actions"},
                    ],
                    "high_risk_ports": [3389, 22, 23, 445, 135, 139, 1433, 3306, 5432, 1521, 27017, 6379, 9200],
                },
            }

            fw = framework_checks.get(framework, framework_checks["general"])
            high_risk_ports = fw["high_risk_ports"]

            # Get workloads
            params = {"include": "labels", "max_results": 10000}
            filter_labels = []
            if app_name:
                app_labels = pce.labels.get(params={"key": "app", "value": app_name})
                if app_labels:
                    filter_labels.append(app_labels[0].href)
            if env_name:
                env_labels = pce.labels.get(params={"key": "env", "value": env_name})
                if env_labels:
                    filter_labels.append(env_labels[0].href)
            if filter_labels:
                params["labels"] = json.dumps(filter_labels)

            workloads = pce.workloads.get(params=params)

            # Build label map
            label_href_map = {}
            for l in pce.labels.get(params={'max_results': 10000}):
                label_href_map[l.href] = {"key": l.key, "value": l.value}

            # Analyze enforcement modes
            enforcement_modes = {}
            idle_workloads = []
            vis_only_workloads = []
            for w in workloads:
                mode = getattr(w, 'enforcement_mode', 'unknown') or 'unknown'
                enforcement_modes[mode] = enforcement_modes.get(mode, 0) + 1
                if mode == 'idle':
                    idle_workloads.append(w.name or w.hostname or w.href)
                elif mode == 'visibility_only':
                    vis_only_workloads.append(w.name or w.hostname or w.href)

            # Query traffic
            start_date = (datetime.now() - timedelta(days=lookback_days)).strftime('%Y-%m-%d')
            end_date = datetime.now().strftime('%Y-%m-%d')

            query_kwargs = {
                "start_date": start_date,
                "end_date": end_date,
                "policy_decisions": ["allowed", "potentially_blocked", "blocked"],
                "max_results": MCP_BUG_MAX_RESULTS,
                "query_name": "compliance-check"
            }

            if app_name and filter_labels:
                filters = [TrafficQueryFilter(label=Reference(href=h)) for h in filter_labels]
                query_kwargs["include_destinations"] = [filters]
                query_kwargs["include_sources"] = [[]]
            else:
                pass  # Query all traffic

            traffic_query = TrafficQuery.build(**query_kwargs)
            flows = pce.get_traffic_flows_async(query_name='compliance-check', traffic_query=traffic_query)
            df = to_dataframe(flows)

            # Run compliance checks
            findings = []
            passed = 0
            failed = 0
            warnings = 0

            for check in fw["checks"]:
                finding = {"id": check["id"], "name": check["name"], "description": check["description"]}

                if "segmentation" in check["name"].lower() or "ringfence" in check["name"].lower() or check["id"] in ("SEG-1", "PCI-6.1", "CIS-9", "CIS-12"):
                    # Check if ringfence exists
                    if app_name:
                        rulesets = pce.rule_sets.get(params={"name": f"RF-{app_name}"})
                        if rulesets:
                            finding["status"] = "PASS"
                            finding["detail"] = f"Ringfence ruleset found for {app_name}"
                            passed += 1
                        else:
                            finding["status"] = "FAIL"
                            finding["detail"] = f"No ringfence ruleset found for {app_name} — run create-ringfence"
                            failed += 1
                    else:
                        # Check total rulesets
                        all_rulesets = pce.rule_sets.get(params={"max_results": 1000})
                        rf_count = sum(1 for rs in all_rulesets if rs.name and rs.name.startswith("RF-"))
                        finding["status"] = "INFO"
                        finding["detail"] = f"{rf_count} ringfence rulesets found out of {len(all_rulesets)} total rulesets"
                        warnings += 1

                elif "enforcement" in check["name"].lower() or check["id"] == "SEG-2":
                    if idle_workloads:
                        finding["status"] = "FAIL"
                        finding["detail"] = f"{len(idle_workloads)} workloads in idle mode: {idle_workloads[:5]}"
                        failed += 1
                    elif vis_only_workloads and env_name and env_name.lower() in ('production', 'prod'):
                        finding["status"] = "WARNING"
                        finding["detail"] = f"{len(vis_only_workloads)} production workloads in visibility_only mode"
                        warnings += 1
                    else:
                        finding["status"] = "PASS"
                        finding["detail"] = f"All {len(workloads)} workloads have appropriate enforcement modes"
                        passed += 1

                elif "high-risk" in check["name"].lower() or "port" in check["name"].lower() or check["id"] in ("SEG-3", "PCI-2.1"):
                    if not df.empty and 'port' in df.columns:
                        exposed_high_risk = df[df['port'].isin(high_risk_ports)]
                        if not exposed_high_risk.empty:
                            uncovered = exposed_high_risk[exposed_high_risk.get('policy_decision', pd.Series()) != 'allowed'] if 'policy_decision' in exposed_high_risk.columns else pd.DataFrame()
                            ports_found = sorted(exposed_high_risk['port'].unique().tolist())
                            if not uncovered.empty:
                                finding["status"] = "FAIL"
                                finding["detail"] = f"High-risk ports with uncovered traffic: {ports_found}"
                                failed += 1
                            else:
                                finding["status"] = "PASS"
                                finding["detail"] = f"High-risk ports {ports_found} are all covered by policy"
                                passed += 1
                        else:
                            finding["status"] = "PASS"
                            finding["detail"] = "No high-risk port traffic detected"
                            passed += 1
                    else:
                        finding["status"] = "INFO"
                        finding["detail"] = "No traffic data available for port analysis"
                        warnings += 1

                elif "coverage" in check["name"].lower() or "flow" in check["name"].lower() or check["id"] in ("SEG-4", "AC-4", "SC-7"):
                    if not df.empty and 'policy_decision' in df.columns:
                        total = len(df)
                        allowed = len(df[df['policy_decision'] == 'allowed'])
                        coverage_pct = round(allowed / total * 100, 1) if total > 0 else 0
                        if coverage_pct >= 90:
                            finding["status"] = "PASS"
                            finding["detail"] = f"{coverage_pct}% of traffic covered by policy ({allowed}/{total} flows)"
                            passed += 1
                        elif coverage_pct >= 50:
                            finding["status"] = "WARNING"
                            finding["detail"] = f"Only {coverage_pct}% of traffic covered ({allowed}/{total} flows)"
                            warnings += 1
                        else:
                            finding["status"] = "FAIL"
                            finding["detail"] = f"Only {coverage_pct}% of traffic covered ({allowed}/{total} flows) — significant policy gaps"
                            failed += 1
                    else:
                        finding["status"] = "INFO"
                        finding["detail"] = "No traffic data available for coverage analysis"
                        warnings += 1

                else:
                    # Default: check traffic patterns
                    if not df.empty and 'policy_decision' in df.columns:
                        blocked = len(df[df['policy_decision'] == 'blocked'])
                        pot_blocked = len(df[df['policy_decision'] == 'potentially_blocked'])
                        if blocked > 0:
                            finding["status"] = "WARNING"
                            finding["detail"] = f"{blocked} blocked and {pot_blocked} potentially blocked flows detected"
                            warnings += 1
                        else:
                            finding["status"] = "PASS"
                            finding["detail"] = "No blocked traffic detected"
                            passed += 1
                    else:
                        finding["status"] = "INFO"
                        finding["detail"] = "No traffic data for analysis"
                        warnings += 1

                findings.append(finding)

            total_checks = passed + failed + warnings
            compliance_score = round(passed / total_checks * 100, 1) if total_checks > 0 else 0

            # Map framework key to resource URI for detailed guidance
            framework_resource_map = {
                "pci-dss": "illumio://compliance/pci-dss",
                "dora": "illumio://compliance/dora",
                "nist": "illumio://compliance/nist-800-53",
                "iso-27001": "illumio://compliance/iso-27001",
                "swift-csp": "illumio://compliance/swift-csp",
                "hipaa": "illumio://compliance/hipaa",
                "cis": "illumio://compliance/cis-controls",
                "general": "illumio://compliance/segmentation-methodology",
            }

            result = {
                "framework": fw["name"],
                "resource_uri": framework_resource_map.get(framework, "illumio://compliance/segmentation-methodology"),
                "resource_hint": f"Read the resource at {framework_resource_map.get(framework, 'illumio://compliance/segmentation-methodology')} for detailed {fw['name']} guidance and remediation steps",
                "scope": {
                    "app": app_name or "all",
                    "env": env_name or "all",
                    "lookback_days": lookback_days
                },
                "compliance_score": compliance_score,
                "summary": {
                    "total_checks": total_checks,
                    "passed": passed,
                    "failed": failed,
                    "warnings": warnings
                },
                "workloads_analyzed": len(workloads),
                "enforcement_modes": enforcement_modes,
                "findings": findings,
                "recommendation": (
                    "Compliant — maintain current policies" if compliance_score >= 90
                    else "Mostly compliant — address failed checks" if compliance_score >= 70
                    else "Significant gaps — prioritize failed findings" if compliance_score >= 40
                    else "Major compliance gaps — immediate remediation needed"
                )
            }

            return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

        except Exception as e:
            error_msg = f"Failed to run compliance check: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

    elif name == "create-service":
        logger.debug(f"CREATE SERVICE CALLED with arguments: {json.dumps(arguments, indent=2)}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            payload = {
                "name": arguments["name"],
                "service_ports": arguments["service_ports"],
            }
            if arguments.get("description"):
                payload["description"] = arguments["description"]

            resp = pce.post("/sec_policy/draft/services", json=payload)
            result = resp.json()

            return [types.TextContent(
                type="text",
                text=json.dumps({"message": "Successfully created service", "service": result}, indent=2)
            )]
        except Exception as e:
            error_msg = f"Failed to create service: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

    elif name == "update-service":
        logger.debug(f"UPDATE SERVICE CALLED with arguments: {json.dumps(arguments, indent=2)}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            # Find service by href or name
            service_href = None
            if arguments.get("href"):
                service_href = arguments["href"]
            elif arguments.get("name"):
                services = pce.services.get(params={"name": arguments["name"]})
                if services:
                    service_href = services[0].href
                else:
                    return [types.TextContent(type="text", text=json.dumps({"error": f"Service '{arguments['name']}' not found"}))]

            if not service_href:
                return [types.TextContent(type="text", text=json.dumps({"error": "Must provide either 'href' or 'name'"}))]

            if '/active/' in service_href:
                service_href = service_href.replace('/active/', '/draft/')

            update_data = {}
            if "new_name" in arguments:
                update_data["name"] = arguments["new_name"]
            if "description" in arguments:
                update_data["description"] = arguments["description"]
            if "service_ports" in arguments:
                update_data["service_ports"] = arguments["service_ports"]

            if not update_data:
                return [types.TextContent(type="text", text=json.dumps({"error": "No update fields provided"}))]

            pce.put(service_href, json=update_data)

            return [types.TextContent(
                type="text",
                text=json.dumps({"message": f"Successfully updated service {service_href}", "updated_fields": list(update_data.keys())}, indent=2)
            )]
        except Exception as e:
            error_msg = f"Failed to update service: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

    elif name == "delete-service":
        logger.debug(f"DELETE SERVICE CALLED with arguments: {json.dumps(arguments, indent=2)}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            service_href = None
            if arguments.get("href"):
                service_href = arguments["href"]
            elif arguments.get("name"):
                services = pce.services.get(params={"name": arguments["name"]})
                if services:
                    service_href = services[0].href
                else:
                    return [types.TextContent(type="text", text=json.dumps({"error": f"Service '{arguments['name']}' not found"}))]

            if not service_href:
                return [types.TextContent(type="text", text=json.dumps({"error": "Must provide either 'href' or 'name'"}))]

            if '/active/' in service_href:
                service_href = service_href.replace('/active/', '/draft/')

            pce.delete(service_href)

            return [types.TextContent(
                type="text",
                text=json.dumps({"message": f"Successfully deleted service {service_href}"}, indent=2)
            )]
        except Exception as e:
            error_msg = f"Failed to delete service: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

def to_dataframe(flows):
    pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
    pce.set_credentials(API_KEY, API_SECRET)

    label_href_map = {}
    value_href_map = {}
    for l in pce.labels.get(params={'max_results': 10000}):
        label_href_map[l.href] = {"key": l.key, "value": l.value}
        value_href_map["{}={}".format(l.key, l.value)] = l.href

    if not flows:
        logger.warning("Warning: Empty flows list received.")
        return pd.DataFrame()

    series_array = []
    for flow in flows:
        try:
            f = {
                'src_ip': flow.src.ip,
                'src_hostname': flow.src.workload.name if flow.src.workload is not None else None,
                'dst_ip': flow.dst.ip,
                'dst_hostname': flow.dst.workload.name if flow.dst.workload is not None else None,
                'proto': flow.service.proto,
                'port': flow.service.port,
                'process_name': flow.service.process_name,
                'service_name': flow.service.service_name,
                'policy_decision': flow.policy_decision,
                'flow_direction': flow.flow_direction,
                'num_connections': flow.num_connections,
                'first_detected': flow.timestamp_range.first_detected,
                'last_detected': flow.timestamp_range.last_detected,
            }

            # Add IP list names for src and dst
            if flow.src.ip_lists:
                ip_list_names = [ipl.name for ipl in flow.src.ip_lists if hasattr(ipl, 'name') and ipl.name]
                f['src_ip_lists'] = ', '.join(ip_list_names) if ip_list_names else None
            else:
                f['src_ip_lists'] = None

            if flow.dst.ip_lists:
                ip_list_names = [ipl.name for ipl in flow.dst.ip_lists if hasattr(ipl, 'name') and ipl.name]
                f['dst_ip_lists'] = ', '.join(ip_list_names) if ip_list_names else None
            else:
                f['dst_ip_lists'] = None

            # Add src and dst labels from workloads
            if flow.src.workload:
                for l in flow.src.workload.labels:
                    if l.href in label_href_map:
                        key = label_href_map[l.href]['key']
                        value = label_href_map[l.href]['value']
                        f[f'src_{key}'] = value

            if flow.dst.workload:
                for l in flow.dst.workload.labels:
                    if l.href in label_href_map:
                        key = label_href_map[l.href]['key']
                        value = label_href_map[l.href]['value']
                        f[f'dst_{key}'] = value

            series_array.append(f)
        except AttributeError as e:
            logger.debug(f"Error processing flow: {e}")
            logger.debug(f"Flow object: {flow}")

    df = pd.DataFrame(series_array)
    return df
  
def summarize_traffic(df):
    logger.debug(f"Summarizing traffic with dataframe: {df}")
    
    # Define all possible group columns, including IP list columns and policy decision
    potential_columns = [
        'src_app', 'src_env', 'src_ip_lists',
        'dst_app', 'dst_env', 'dst_ip_lists',
        'proto', 'port', 'policy_decision'
    ]

    # Filter to only use columns that exist in the DataFrame
    group_columns = [col for col in potential_columns if col in df.columns]

    if not group_columns:
        logger.warning("No grouping columns found in DataFrame")
        return "No traffic data available for summarization"

    if df.empty:
        logger.warning("Empty DataFrame received")
        return "No traffic data available for summarization"

    # Fill NaN in IP list columns so groupby works properly
    for col in ['src_ip_lists', 'dst_ip_lists']:
        if col in df.columns:
            df[col] = df[col].fillna('')

    logger.debug(f"Using group columns: {group_columns}")
    logger.debug(f"DataFrame shape before grouping: {df.shape}")
    logger.debug(f"DataFrame columns: {df.columns.tolist()}")
    logger.debug(f"First few rows of DataFrame:\n{df.head()}")

    # Group by available columns
    summary = df.groupby(group_columns)['num_connections'].sum().reset_index()

    logger.debug(f"Summary shape after grouping: {summary.shape}")
    logger.debug(f"Summary columns: {summary.columns.tolist()}")
    logger.debug(f"First few rows of summary:\n{summary.head()}")

    # Sort by number of connections in descending order
    summary = summary.sort_values('num_connections', ascending=False)

    # Convert to a more readable format
    summary_list = []
    for _, row in summary.iterrows():
        # Build source info: prefer app/env labels, fall back to IP list name
        src_info = []
        if 'src_app' in row and row['src_app']:
            src_info.append(row['src_app'])
        if 'src_env' in row and row['src_env']:
            src_info.append(f"({row['src_env']})")
        if not src_info and 'src_ip_lists' in row and row['src_ip_lists']:
            src_info.append(f"[IPList: {row['src_ip_lists']}]")
        src_str = " ".join(src_info) if src_info else "Unknown Source"

        # Build destination info: prefer app/env labels, fall back to IP list name
        dst_info = []
        if 'dst_app' in row and row['dst_app']:
            dst_info.append(row['dst_app'])
        if 'dst_env' in row and row['dst_env']:
            dst_info.append(f"({row['dst_env']})")
        if not dst_info and 'dst_ip_lists' in row and row['dst_ip_lists']:
            dst_info.append(f"[IPList: {row['dst_ip_lists']}]")
        dst_str = " ".join(dst_info) if dst_info else "Unknown Destination"

        if src_str != dst_str:
            port_info = f"port {row['port']}" if 'port' in row else "unknown port"
            proto_info = f"proto {row['proto']}" if 'proto' in row else ""
            policy = row.get('policy_decision', '') if 'policy_decision' in row.index else ''
            policy_str = f" [{policy}]" if policy else ""
            summary_list.append(
                f"From {src_str} to {dst_str} on {port_info} {proto_info}: {row['num_connections']} connections{policy_str}"
            )

    if not summary_list:
        return "No traffic patterns to summarize"

    return "\n".join(summary_list)

async def main():
    # Run the server using stdin/stdout streams
    logger.debug("Starting server")
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="illumio-mcp",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

class ServicePortEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ServicePort):
            return {
                'port': obj.port,
                'protocol': obj.protocol
            }
        return super().default(obj)