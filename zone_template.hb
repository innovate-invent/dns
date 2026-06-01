{{! RuleTypes =
ZoneFile: Array
//Directive: String
RR: Object
Owner: String
TTL: String
RRType: String
RData: String
DomainName: Array
DomainLabel: String
//Comment: String
~}}
{{#each . }}{{ignore (lastSeen Owner) ~}}
{{#unless (isNSEC3 . ) }}
{{lastSeen Owner}} {{TTL}} {{RRType}} {{shrinkWhitespace (truncateAt RData ';') }}
{{/unless ~}}
{{/each}}