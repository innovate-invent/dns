{{#each . ~}}
view "{{#each ZoneNames}}{{#each DomainName}}{{.}}.{{/each}} {{/each}}" {
    match-destinations { {{#each bind }}{{IPv4address}}{{IPv6address}}; {{/each}}
    port 53
    {{#each file}}zone "{{#each DomainName}}{{.}}.{{/each}}" {
    type {{#if (isMirror .. ) }}primary{{/if}}{{#unless (isMirror .. ) }}mirror # clear the AA bit, but also sets the AD bit which might muck up the test{{/unless}}
        file "{{FilePath}}"
    }
    {{/each}}
}
{{/each }}