'use strict';

const behaviors = [
  { id: 'service-exploitation', name: 'Exploit a reachable service', priority: 'critical', entityTypes: ['service', 'exposure'], survey: { desiredTypes: ['service', 'exposure', 'software'], desiredRelations: ['runs', 'exposed_through'] }, rationale: 'Reachable services cross a trust boundary and can provide execution or data access.' },
  { id: 'credential-abuse', name: 'Abuse an identity or credential', priority: 'high', entityTypes: ['identity', 'credential'], survey: { desiredTypes: ['identity', 'credential'], desiredRelations: ['administers', 'uses', 'authenticates_to'] }, rationale: 'Valid credentials can bypass exploit-focused controls.' },
  { id: 'lateral-movement', name: 'Move between internal systems', priority: 'high', entityTypes: ['endpoint', 'network'], minimumEndpoints: 2, survey: { desiredTypes: ['endpoint', 'network', 'service'], desiredRelations: ['member_of', 'runs'] }, rationale: 'Private reachability can turn one compromised system into broader access.' },
  { id: 'defense-evasion', name: 'Impair telemetry or controls', priority: 'high', entityTypes: ['telemetry', 'control'], survey: { desiredTypes: ['telemetry', 'control'], desiredRelations: ['observes', 'protects'] }, rationale: 'Loss of a small number of sensors creates material blind spots.' },
  { id: 'control-modification', name: 'Modify security or routing controls', priority: 'high', entityTypes: ['control', 'route', 'network'], survey: { desiredTypes: ['control', 'route', 'network'], desiredRelations: ['protects', 'advertises'] }, rationale: 'Policy and routing changes can silently alter reachable terrain.' },
  { id: 'privilege-escalation', name: 'Acquire elevated privilege', priority: 'high', entityTypes: ['identity', 'endpoint'], survey: { desiredTypes: ['identity', 'endpoint'], desiredRelations: ['administers', 'account_on'] }, rationale: 'Privilege changes increase impact and access.' },
  { id: 'persistence', name: 'Establish persistent access', priority: 'high', entityTypes: ['endpoint', 'service', 'credential'], survey: { desiredTypes: ['endpoint', 'service', 'credential', 'software'], desiredRelations: ['runs', 'uses', 'authenticates_to'] }, rationale: 'Long-lived access survives ordinary session termination.' },
  { id: 'resource-access', name: 'Enumerate or access protected resources', priority: 'medium', entityTypes: ['service', 'data_resource'], survey: { desiredTypes: ['service', 'data_resource', 'identity'], desiredRelations: ['stores', 'runs'] }, rationale: 'Resource access provides intent and impact context beyond authentication.' },
  { id: 'data-exfiltration', name: 'Stage and transfer data', priority: 'high', entityTypes: ['data_resource', 'endpoint', 'network'], survey: { desiredTypes: ['data_resource', 'endpoint', 'network'], desiredRelations: ['stores', 'member_of'] }, rationale: 'Unusual staging and outbound transfer can indicate theft.' },
  { id: 'command-and-control', name: 'Maintain external command channel', priority: 'high', entityTypes: ['endpoint', 'network'], survey: { desiredTypes: ['endpoint', 'network', 'service'], desiredRelations: ['member_of', 'runs'] }, rationale: 'Recurring external communication can provide adversary control.' },
  { id: 'discovery', name: 'Discover systems and services', priority: 'medium', entityTypes: ['endpoint', 'network'], survey: { desiredTypes: ['endpoint', 'network', 'service'], desiredRelations: ['member_of', 'runs'] }, rationale: 'Rapid enumeration often precedes lateral movement.' },
  { id: 'impact', name: 'Disrupt availability or recovery', priority: 'critical', entityTypes: ['data_resource', 'service', 'control'], survey: { desiredTypes: ['data_resource', 'service', 'control'], desiredRelations: ['stores', 'runs', 'protects'] }, rationale: 'Backup and service impairment directly affect recovery.' },
  { id: 'data-exposure', name: 'Expose data to an external principal', priority: 'high', entityTypes: ['data_resource', 'exposure', 'service'], survey: { desiredTypes: ['data_resource', 'exposure', 'service'], desiredRelations: ['stores', 'exposed_through'] }, rationale: 'Sharing and access-policy changes can create immediate confidentiality loss.' }
];

function prioritizeBehaviors(graphSnapshot, analytics) {
  const counts = new Map();
  for (const entity of graphSnapshot.entities || []) counts.set(entity.type, (counts.get(entity.type) || 0) + 1);
  const relations = new Set((graphSnapshot.relationships || []).map((item) => item.relation));
  const availableCapabilities = new Set((graphSnapshot.capabilities || []).filter((item) => ['available', 'degraded'].includes(item.status)).map((item) => item.capability));
  return behaviors.map((behavior) => {
    const matchedTypes = behavior.entityTypes.filter((type) => counts.has(type));
    const endpointRequirement = !behavior.minimumEndpoints || (counts.get('endpoint') || 0) >= behavior.minimumEndpoints;
    const applicable = matchedTypes.length > 0 && endpointRequirement;
    const mappedRules = analytics.filter((analytic) => analytic.behavior === behavior.id);
    const rules = mappedRules.map((analytic) => analytic.id).sort();
    const desiredTypes = [...new Set(behavior.survey?.desiredTypes || behavior.entityTypes)].sort();
    const desiredRelations = [...new Set(behavior.survey?.desiredRelations || [])].sort();
    const desiredCapabilities = [...new Set(mappedRules.flatMap((analytic) => [
      ...(analytic.requirements?.all || []), ...(analytic.requirements?.oneOf || []).flat(), ...(analytic.requirements?.optional || [])
    ]))].sort();
    const missingSurvey = {
      entityTypes: desiredTypes.filter((type) => !counts.has(type)),
      relationships: desiredRelations.filter((relation) => !relations.has(relation)),
      capabilities: desiredCapabilities.filter((capability) => !availableCapabilities.has(capability))
    };
    const missingCount = Object.values(missingSurvey).reduce((total, items) => total + items.length, 0);
    const surveyCoverage = !applicable ? 'not_applicable' : missingCount === 0 ? 'full' : availableCapabilities.size ? 'partial' : 'gap';
    return { ...behavior, applicable, matchedTypes, rules, desiredCapabilities, missingSurvey, surveyCoverage, state: !applicable ? 'not_applicable' : rules.length ? 'planned' : 'gap' };
  }).sort((a, b) => a.id.localeCompare(b.id));
}

module.exports = { behaviors, prioritizeBehaviors };
