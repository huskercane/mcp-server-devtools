Read TeamCity builds, build configurations, projects, agents, and queued builds. For example, path `builds` with queryParams `{"locator":"buildType:MyBuild,count:20","fields":"build(id,number,status,webUrl),nextHref"}`.

Generic `GET` against the TeamCity REST API. Paths may be relative (`projects`) or include `/app/rest/` (`/app/rest/projects`); the prefix is added when absent. Configure `TEAMCITY_URL` as the server URL, including any context path but excluding `/app/rest`, and `TEAMCITY_TOKEN` as a personal access token.

Returns TOON by default; use `outputFormat: "json"` for JSON and `jq` for JMESPath filtering. Pass TeamCity `locator` and `fields` through `queryParams`. Pagination is explicit: follow `nextHref` using another call; results are not automatically aggregated.

API reference: https://www.jetbrains.com/help/teamcity/rest/teamcity-rest-api-documentation.html
