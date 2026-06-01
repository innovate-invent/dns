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
    {{#if (isNSEC3 . ) }}
    authority "{{lastSeen Owner}} {{TTL}} {{RRType}} {{shrinkWhitespace (truncateAt RData ';') }}"
    {{/if ~}}
{{/each}}