'use strict';

// Framework mappings are detection-engineering metadata, not claims of
// compliance or complete ATT&CK coverage. `direct` means the analytic observes
// the technique's defining behavior; `correlated` means an ordered chain
// supports it; `contextual` means the event is useful evidence but is not
// sufficient to establish the technique by itself.
const ATTACK_TECHNIQUES = Object.freeze({
  T1021: 'Remote Services',
  T1041: 'Exfiltration Over C2 Channel',
  T1046: 'Network Service Discovery',
  T1059: 'Command and Scripting Interpreter',
  T1071: 'Application Layer Protocol',
  'T1071.004': 'Application Layer Protocol: DNS',
  T1074: 'Data Staged',
  T1078: 'Valid Accounts',
  T1083: 'File and Directory Discovery',
  T1090: 'Proxy',
  T1098: 'Account Manipulation',
  'T1098.001': 'Account Manipulation: Additional Cloud Credentials',
  'T1098.004': 'Account Manipulation: SSH Authorized Keys',
  T1110: 'Brute Force',
  'T1110.003': 'Brute Force: Password Spraying',
  T1136: 'Create Account',
  'T1136.001': 'Create Account: Local Account',
  T1190: 'Exploit Public-Facing Application',
  T1490: 'Inhibit System Recovery',
  T1530: 'Data from Cloud Storage',
  T1543: 'Create or Modify System Process',
  'T1543.002': 'Create or Modify System Process: Systemd Service',
  T1548: 'Abuse Elevation Control Mechanism',
  T1556: 'Modify Authentication Process',
  'T1556.006': 'Modify Authentication Process: Multi-Factor Authentication',
  T1685: 'Disable or Modify Tools',
  'T1685.006': 'Disable or Modify Tools: Clear Linux or Mac System Logs',
  T1686: 'Disable or Modify System Firewall'
});

const NIST_CSF_OUTCOMES = Object.freeze({
  'ID.AM-03': 'Authorized network communications and data flows are represented',
  'ID.AM-07': 'Inventories of designated data and metadata are maintained',
  'PR.AA-01': 'Identities and credentials are managed',
  'PR.AA-05': 'Permissions and authorizations are managed and reviewed',
  'PR.DS-11': 'Backups are created, protected, maintained, and tested',
  'PR.PS-04': 'Log records are generated and available for monitoring',
  'DE.CM-01': 'Networks and network services are monitored',
  'DE.CM-03': 'Personnel activity and technology usage are monitored',
  'DE.CM-06': 'External service provider activity is monitored',
  'DE.CM-09': 'Hardware, software, runtime environments, and data are monitored',
  'DE.AE-02': 'Potentially adverse events are analyzed',
  'DE.AE-03': 'Information is correlated from multiple sources',
  'DE.AE-04': 'Impact and scope of adverse events are determined',
  'DE.AE-07': 'Threat intelligence and context are integrated into analysis',
  'DE.AE-08': 'Incidents are declared using defined criteria'
});

const CISA_CPG_OUTCOMES = Object.freeze({
  '1.A': 'Asset Inventory',
  '2.E': 'Separating User and Privileged Accounts',
  '2.F': 'Network Segmentation',
  '2.G': 'Detection of Unsuccessful (Automated) Login Attempts',
  '2.H': 'Phishing-Resistant Multifactor Authentication',
  '2.L': 'Secure Sensitive Data',
  '2.O': 'Document Device Configurations',
  '2.P': 'Document Network Topology',
  '2.Q': 'Hardware and Software Approval Process',
  '2.R': 'System Backups',
  '2.T': 'Log Collection',
  '2.U': 'Secure Log Storage',
  '2.W': 'No Exploitable Services on the Internet'
});

const FRAMEWORK_SOURCES = Object.freeze({
  mitreAttack: { version: '19.2', retrieved: '2026-08-19', url: 'https://github.com/mitre-attack/attack-stix-data/tree/6cda5ad8462c79e14fbb872f4e09059b18e0cfc4' },
  nistCsf: { version: '2.0', retrieved: '2026-08-19', url: 'https://www.nist.gov/document/nist-csf-20-core-withdrawn-csf-11-elements' },
  cisaCpg: { version: '1.0.1', retrieved: '2026-08-19', url: 'https://www.cisa.gov/sites/default/files/2023-03/CISA_CPG_REPORT_v1.0.1_FINAL.pdf' },
  sigma: { commit: 'da9bb07d642a2826e89702445d32c795209ec108', retrieved: '2026-08-19', url: 'https://github.com/SigmaHQ/sigma/tree/da9bb07d642a2826e89702445d32c795209ec108' },
  elastic: { commit: 'a9208f465f486bf87dd614c463eb5e790d559a52', retrieved: '2026-08-19', url: 'https://github.com/elastic/detection-rules/tree/a9208f465f486bf87dd614c463eb5e790d559a52' },
  splunk: { commit: '4fede6c7c02091185e4187865117b4ef41734d73', retrieved: '2026-08-19', url: 'https://github.com/splunk/security_content/tree/4fede6c7c02091185e4187865117b4ef41734d73' },
  sentinel: { commit: '04549c0e1a731d7b89a56a09cd5202d1b524dcd2', retrieved: '2026-08-19', url: 'https://github.com/Azure/Azure-Sentinel/tree/04549c0e1a731d7b89a56a09cd5202d1b524dcd2' }
});

const ANALOG_FAMILIES = Object.freeze({
  'authentication-abuse': {
    relation: 'semantic',
    references: [
      'https://github.com/SigmaHQ/sigma/blob/da9bb07d642a2826e89702445d32c795209ec108/deprecated/other/generic_brute_force.yml',
      'https://github.com/Azure/Azure-Sentinel/blob/04549c0e1a731d7b89a56a09cd5202d1b524dcd2/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/SigninBruteForce-AzurePortal.yaml'
    ]
  },
  'linux-service-change': {
    relation: 'semantic',
    references: [
      'https://github.com/SigmaHQ/sigma/blob/da9bb07d642a2826e89702445d32c795209ec108/rules/linux/auditd/path/lnx_auditd_systemd_service_creation.yml',
      'https://github.com/splunk/security_content/blob/4fede6c7c02091185e4187865117b4ef41734d73/detections/endpoint/linux_deletion_of_services.yml'
    ]
  },
  'linux-log-tampering': {
    relation: 'semantic',
    references: [
      'https://github.com/SigmaHQ/sigma/blob/da9bb07d642a2826e89702445d32c795209ec108/rules/linux/process_creation/proc_creation_lnx_clear_logs.yml',
      'https://github.com/SigmaHQ/sigma/blob/da9bb07d642a2826e89702445d32c795209ec108/rules/linux/builtin/lnx_clear_syslog.yml'
    ]
  },
  'network-discovery': {
    relation: 'semantic',
    references: [
      'https://github.com/SigmaHQ/sigma/blob/da9bb07d642a2826e89702445d32c795209ec108/rules/application/opencanary/opencanary_portscan_syn_scan.yml'
    ]
  },
  'defense-control-change': {
    relation: 'supporting',
    references: [
      'https://github.com/elastic/detection-rules/blob/a9208f465f486bf87dd614c463eb5e790d559a52/rules/windows/privilege_escalation_disable_uac_registry.toml'
    ]
  },
  'recovery-impairment': {
    relation: 'semantic',
    references: [
      'https://github.com/SigmaHQ/sigma/blob/da9bb07d642a2826e89702445d32c795209ec108/rules/cloud/aws/cloudtrail/aws_disable_bucket_versioning.yml'
    ]
  }
});

const m = (attack, nist, cisa, analogs = []) => Object.freeze({ attack, nist, cisa, analogs });
const a = (id, relation = 'direct') => Object.freeze({ id, relation });

const RULE_FRAMEWORK_MAPPINGS = Object.freeze({
  'auth-failure-burst': m([a('T1110')], ['DE.CM-03', 'DE.AE-02'], ['2.G', '2.T'], ['authentication-abuse']),
  'auth-source-many-identities': m([a('T1110.003')], ['DE.CM-03', 'DE.AE-02'], ['2.G', '2.T'], ['authentication-abuse']),
  'auth-identity-many-targets': m([a('T1078', 'contextual')], ['DE.CM-03', 'DE.AE-02'], ['2.G', '2.T'], ['authentication-abuse']),
  'auth-failure-then-success': m([a('T1110', 'correlated'), a('T1078', 'correlated')], ['DE.CM-03', 'DE.AE-02', 'DE.AE-03'], ['2.G', '2.T'], ['authentication-abuse']),
  'remote-auth-then-execution': m([a('T1021', 'correlated'), a('T1078', 'correlated')], ['DE.CM-03', 'DE.CM-09', 'DE.AE-03'], ['2.F', '2.T']),
  'remote-auth-then-privilege-use': m([a('T1548', 'correlated'), a('T1078', 'correlated')], ['DE.CM-03', 'DE.CM-09', 'DE.AE-03'], ['2.E', '2.T']),
  'remote-auth-then-account-created': m([a('T1136.001', 'correlated')], ['DE.CM-03', 'DE.CM-09', 'DE.AE-03'], ['2.E', '2.T']),
  'remote-auth-then-persistence': m([a('T1543.002', 'correlated')], ['DE.CM-03', 'DE.CM-09', 'DE.AE-03'], ['2.Q', '2.T'], ['linux-service-change']),
  'remote-auth-then-listener-created': m([a('T1021', 'correlated'), a('T1543', 'correlated')], ['DE.CM-01', 'DE.CM-09', 'DE.AE-03'], ['2.W', '2.T']),
  'service-spawned-command-interpreter': m([a('T1190', 'correlated'), a('T1059')], ['DE.CM-09', 'DE.AE-02', 'DE.AE-04'], ['2.W', '2.T']),
  'telemetry-disabled': m([a('T1685')], ['PR.PS-04', 'DE.CM-09', 'DE.AE-02'], ['2.T'], ['defense-control-change']),
  'security-log-cleared': m([a('T1685.006')], ['PR.PS-04', 'DE.CM-09', 'DE.AE-02'], ['2.U'], ['linux-log-tampering']),
  'security-policy-changed': m([a('T1686', 'contextual')], ['DE.CM-01', 'DE.CM-06', 'DE.AE-02'], ['2.O', '2.T'], ['defense-control-change']),
  'route-or-exit-node-enabled': m([a('T1090', 'contextual')], ['ID.AM-03', 'DE.CM-01', 'DE.AE-02'], ['2.P', '2.T']),
  'privileged-role-granted': m([a('T1098')], ['PR.AA-05', 'DE.CM-03', 'DE.AE-02'], ['2.E', '2.T']),
  'mfa-protection-disabled': m([a('T1556.006')], ['PR.AA-01', 'PR.AA-05', 'DE.AE-02'], ['2.H', '2.T']),
  'credential-created': m([a('T1098', 'contextual'), a('T1098.001', 'contextual')], ['PR.AA-01', 'DE.CM-03', 'DE.AE-02'], ['2.E', '2.T']),
  'privileged-ssh-credential-changed': m([a('T1098.004')], ['PR.AA-01', 'PR.AA-05', 'DE.CM-09', 'DE.AE-02'], ['2.E', '2.T']),
  'local-account-created': m([a('T1136.001')], ['PR.AA-01', 'DE.CM-09', 'DE.AE-02'], ['2.E', '2.T']),
  'persistent-service-created': m([a('T1543.002')], ['DE.CM-09', 'DE.AE-02'], ['2.Q', '2.T'], ['linux-service-change']),
  'new-or-unapproved-access': m([a('T1078', 'contextual')], ['DE.CM-01', 'DE.CM-03', 'DE.CM-06', 'DE.AE-02'], ['2.Q', '2.T']),
  'authorization-failure-burst': m([a('T1083', 'contextual')], ['DE.CM-03', 'DE.AE-02'], ['2.T']),
  'resource-enumeration': m([a('T1083', 'contextual')], ['DE.CM-03', 'DE.CM-06', 'DE.AE-02'], ['2.T']),
  'large-egress-transfer': m([a('T1041', 'contextual')], ['DE.CM-01', 'DE.AE-02', 'DE.AE-04'], ['2.L', '2.T']),
  'dns-failure-burst': m([a('T1071.004', 'contextual')], ['DE.CM-01', 'DE.AE-02'], ['2.T']),
  'network-destination-scan': m([a('T1046')], ['DE.CM-01', 'DE.AE-02'], ['2.P', '2.T'], ['network-discovery']),
  'backup-protection-disabled': m([a('T1490')], ['PR.DS-11', 'DE.CM-09', 'DE.AE-02'], ['2.R', '2.T'], ['recovery-impairment']),
  'public-share-created': m([a('T1530', 'contextual')], ['DE.CM-06', 'DE.AE-02', 'DE.AE-04'], ['2.L', '2.T']),
  'data-staging-then-egress': m([a('T1074', 'correlated'), a('T1041', 'correlated')], ['DE.CM-01', 'DE.CM-09', 'DE.AE-03', 'DE.AE-04'], ['2.L', '2.T']),
  'network-listener-created': m([a('T1543', 'contextual')], ['DE.CM-01', 'DE.CM-09', 'DE.AE-02'], ['2.W', '2.T']),
  'security-control-disabled': m([a('T1685')], ['DE.CM-09', 'DE.AE-02'], ['2.T'], ['defense-control-change']),
  'sensitive-resource-created': m([a('T1074', 'contextual')], ['ID.AM-07', 'DE.CM-06', 'DE.AE-02'], ['1.A', '2.L'])
});

function attachFrameworkMappings(rules) {
  return rules.map((rule) => ({ ...rule, frameworks: structuredClone(RULE_FRAMEWORK_MAPPINGS[rule.id]) }));
}

module.exports = {
  ATTACK_TECHNIQUES,
  NIST_CSF_OUTCOMES,
  CISA_CPG_OUTCOMES,
  FRAMEWORK_SOURCES,
  ANALOG_FAMILIES,
  RULE_FRAMEWORK_MAPPINGS,
  attachFrameworkMappings
};
