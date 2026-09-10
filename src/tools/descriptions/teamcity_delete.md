Delete TeamCity resources, for example path `builds/id:123`. This is destructive; confirm the intended resource before calling.

Generic `DELETE` against the TeamCity REST API. Paths may be relative (`projects`) or include `/app/rest/` (`/app/rest/projects`); the prefix is added when absent. Configure `TEAMCITY_URL` as the server URL, including any context path but excluding `/app/rest`, and `TEAMCITY_TOKEN` as a personal access token.

Returns TOON by default; use `outputFormat: "json"` for JSON and `jq` for JMESPath filtering. Pass TeamCity `locator` and `fields` through `queryParams`. Pagination is explicit: follow `nextHref` using another call; results are not automatically aggregated.

API reference: https://www.jetbrains.com/help/teamcity/rest/teamcity-rest-api-documentation.html
